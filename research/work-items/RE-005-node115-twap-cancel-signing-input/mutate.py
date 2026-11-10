#!/usr/bin/env python3
"""Compiled-mutation check for the RE-005 twapCancel signing-input crate.

Copies the crate and its path dependencies into a sandbox under a NEW --outdir,
applies one source mutation at a time, and for each mutant and profile:
  1. builds the tests (`cargo test --no-run`)  -> a build failure is an error,
  2. runs the test binaries (`cargo test --no-fail-fast`) and parses the names
     of the tests that failed.
A mutant counts as killed only if the build succeeded, the full test count ran,
and at least one of the mutant's *expected* tests failed. Survivors, builds that
fail, runs that do not execute every test, wrong-test failures and tool
environment errors all give a non-zero exit. The repository and the packet are
only read.

  mutate.py --outdir NEW_DIR [--profiles debug,release] [--cargo cargo]
  mutate.py --outdir NEW_DIR --selftest

Exit: 0 every mutant killed by an expected test in every profile; 1 any
failure; 2 usage; 3 environment; 4 outdir refused.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

PACKET = os.path.dirname(os.path.abspath(__file__))
CRATE = "node115-twap-cancel-signing-input"
SRC_DIRS = [CRATE, "node115-twap-action-wire", "node115-quantity-preparation-adapter",
            "node115-quantity-preparation", "node115-sponge-permutation"]
LIB = CRATE + "/src/lib.rs"
SPONGE = "node115-sponge-permutation/lib.rs"
EXPECTED_TESTS = 11

P_ORACLE = "preimage_matches_oracle"
D_ORACLE = "digest_matches_oracle"
T_ORACLE = "tag_matches_oracle"
R_ORACLE = "returned_record_matches_oracle"

# (id, file, old text (exactly once), new text, expected failing tests, what it models)
MUTANTS = [
    ("M01-map-header-count", LIB, "p.push(0x80 | 3);", "p.push(0x80 | 2);", [P_ORACLE], "fixmap length 3 -> 2"),
    ("M02-key-a-to-t", LIB, 'p.fixstr(b"a");', 'p.fixstr(b"t");', [P_ORACLE], "field order/name: first key a -> t"),
    ("M03-type-key-text", LIB, 'p.fixstr(b"type");', 'p.fixstr(b"typo");', [P_ORACLE], "type key text"),
    ("M04-action-name-case", LIB, 'b"twapCancel"', 'b"twapcancel"', [P_ORACLE], "action name case"),
    ("M05-fixint-boundary", LIB, "if n < 128 {", "if n < 127 {", [P_ORACLE], "integer width: 127 boundary"),
    ("M06-u8-boundary", LIB, "} else if n < 256 {", "} else if n < 255 {", [P_ORACLE], "integer width: 255 boundary"),
    ("M07-u16-boundary", LIB, "} else if n < 65536 {", "} else if n < 65535 {", [P_ORACLE], "integer width: 65535 boundary"),
    ("M08-u32-boundary", LIB, "} else if n <= u64::from(u32::MAX) {", "} else if n < u64::from(u32::MAX) {", [P_ORACLE], "integer width: u32 max boundary"),
    ("M09-u8-marker", LIB, "self.push(0xcc);", "self.push(0xcd);", [P_ORACLE], "uint8 marker byte"),
    ("M10-u32-marker", LIB, "self.push(0xce);", "self.push(0xcf);", [P_ORACLE], "uint32 marker byte"),
    ("M11-u16-endian", LIB, "self.extend(&(n as u16).to_be_bytes());", "self.extend(&(n as u16).to_le_bytes());", [P_ORACLE], "u16 byte order"),
    ("M12-nonce-endian", LIB, "p.extend(&suffix.nonce.to_be_bytes());", "p.extend(&suffix.nonce.to_le_bytes());", [P_ORACLE], "nonce byte order"),
    ("M13-vault-marker", LIB, "            p.push(1);\n", "            p.push(2);\n", [P_ORACLE], "suffix flag: present-vault marker"),
    ("M14-absent-vault-marker", LIB, "None => p.push(0),", "None => p.push(1),", [P_ORACLE], "suffix flag: absent-vault marker"),
    ("M15-vault-length", LIB, "p.extend(&vault);", "p.extend(&vault[..19]);", [P_ORACLE], "vault copy width"),
    ("M16-expiry-endian", LIB, "p.extend(&expiry.to_be_bytes());", "p.extend(&expiry.to_le_bytes());", [P_ORACLE], "expiry byte order"),
    ("M17-expiry-marker", LIB, "        p.push(0);\n        p.extend(&expiry", "        p.push(1);\n        p.extend(&expiry", [P_ORACLE], "suffix flag: expiry marker byte"),
    ("M18-expiry-needs-vault", LIB, "if let Some(expiry) = suffix.expires_after {",
     "if let (Some(_), Some(expiry)) = (suffix.vault, suffix.expires_after) {", [P_ORACLE], "suffix flag: expiry gated on vault"),
    ("M19-domain-byte", LIB, "block[data.len()] ^= 0x01;", "block[data.len()] ^= 0x06;", [D_ORACLE], "padding byte: SHA3 domain instead of Keccak"),
    ("M20-final-pad-position", LIB, "block[RATE - 1] ^= 0x80;", "block[RATE - 2] ^= 0x80;", [D_ORACLE], "padding byte position"),
    ("M21-rate", LIB, "pub const RATE: usize = 136;", "pub const RATE: usize = 135;", [D_ORACLE], "rate 136 -> 135"),
    ("M22-digest-lane-order", LIB, "digest.chunks_exact_mut(8).zip(&lanes)", "digest.chunks_exact_mut(8).zip(lanes.iter().rev())", [D_ORACLE], "squeeze lane order"),
    ("M23-tag-three", LIB, "pub const TAG_SELECTOR_THREE: u8 = 0x61;", "pub const TAG_SELECTOR_THREE: u8 = 0x62;", [T_ORACLE], "chain tag for selector 3"),
    ("M24-selector-width", LIB, "if selector as u8 == 3 {", "if selector == 3 {", [T_ORACLE, "selector_uses_low_byte_only"], "tag looks at the whole selector"),
    ("M25-record-constant", LIB, "pub const RECORD_CONSTANT: u64 = 0x539;", "pub const RECORD_CONSTANT: u64 = 0x538;", [R_ORACLE, "anchor_literals_typed_by_hand"], "constant 1337 -> 1336"),
    ("M26-record-pointer-slot", LIB, "words[1] = tag_address;", "words[2] = tag_address;", [R_ORACLE], "record word order"),
    ("M27-record-digest-endian", LIB, "*word = u64::from_le_bytes(chunk.try_into().unwrap());", "*word = u64::from_be_bytes(chunk.try_into().unwrap());", [R_ORACLE], "record digest word byte order"),
    ("M28-asset-width", LIB, "p.uint(u64::from(cancel.asset));", "p.uint(u64::from(cancel.asset as u8));", [P_ORACLE], "asset narrowed to u8"),
    ("M29-block-limit", LIB, "if data.len() >= RATE {", "if data.len() > RATE {", ["keccak_public_vectors_and_block_limit"], "one-block limit off by one"),
    ("M30-dep-round-constant", SPONGE, "0x8000000080008008,", "0x8000000080008009,", [D_ORACLE, "keccak_public_vectors_and_block_limit"], "dependency: last round constant"),
    ("M31-dep-rho-offset", SPONGE, "0, 1, 62, 28, 27,", "0, 1, 63, 28, 27,", [D_ORACLE, "keccak_public_vectors_and_block_limit"], "dependency: rho offset"),
]

TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", re.M)
RESULT_LINE = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed", re.M)


class Env(Exception):
    pass


LOG = []


def say(msg):
    """Print a selftest line and keep it for selftest.txt in the outdir."""
    print(msg)
    LOG.append(msg)


def cargo(argv, cargo_bin, manifest, target, release, extra=()):
    cmd = [cargo_bin] + argv + ["--offline", "--locked", "--manifest-path", manifest, "--target-dir", target]
    if release:
        cmd.append("--release")
    cmd += list(extra)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                              env=dict(os.environ, CARGO_TERM_COLOR="never"))
    except (OSError, subprocess.SubprocessError) as exc:
        raise Env("cannot run cargo: %s" % exc)


def evaluate(sandbox, outdir, cargo_bin, profile, expected):
    """-> (status, tests_run, failed_tests). Build and test run are separate commands."""
    manifest = os.path.join(sandbox, CRATE, "Cargo.toml")
    target = os.path.join(outdir, "target-" + profile)
    release = profile == "release"
    built = cargo(["test", "--no-run"], cargo_bin, manifest, target, release)
    if built.returncode != 0:
        return "build-error", 0, []
    ran = cargo(["test"], cargo_bin, manifest, target, release, ["--no-fail-fast"])
    results = TEST_LINE.findall(ran.stdout)
    run_count = sum(int(p) + int(f) for p, f in RESULT_LINE.findall(ran.stdout))
    failed = sorted(name for name, res in results if res == "FAILED")
    if run_count != EXPECTED_TESTS:
        return "tests-not-run", run_count, failed
    if ran.returncode == 0 and not failed:
        return "survived", run_count, failed
    if not failed:
        return "run-error", run_count, failed
    if expected and not set(failed) & set(expected):
        return "wrong-test", run_count, failed
    return "killed", run_count, failed


def copy_sandbox(repo, outdir):
    sandbox = os.path.join(outdir, "sandbox", "src")
    for d in SRC_DIRS:
        shutil.copytree(os.path.join(repo, "src", d), os.path.join(sandbox, d),
                        ignore=shutil.ignore_patterns("target"))
    return sandbox


def run(args, mutants):
    repo = os.path.realpath(args.repo_root)
    outdir = args.outdir
    os.makedirs(outdir)
    if shutil.which(args.cargo) is None:
        raise Env("cargo not found")
    sandbox = copy_sandbox(repo, outdir)
    profiles = args.profiles.split(",")
    rows, bad = [], 0
    for profile in profiles:
        status, count, failed = evaluate(sandbox, outdir, args.cargo, profile, None)
        rows.append(("BASELINE", profile, status, count, ",".join(failed), ""))
        if status != "survived":  # an unmutated crate must pass everything
            print("mutate: baseline (%s) is not clean: %s %s" % (profile, status, failed))
            write_rows(outdir, rows)
            return 1
    print("mutate: baseline clean in %s (%d tests each)" % (",".join(profiles), EXPECTED_TESTS))
    for mid, rel, old, new, expected, model in sorted(mutants, key=lambda m: m[0]):
        path = os.path.join(sandbox, rel)
        with open(path, newline="") as fh:
            original = fh.read()
        if original.count(old) != 1:
            rows.append((mid, "-", "bad-pattern", 0, "", "pattern occurs %d times" % original.count(old)))
            print("mutate: %s bad-pattern (occurs %d times, need exactly 1)" % (mid, original.count(old)))
            bad += 1
            continue
        with open(path, "w", newline="") as fh:
            fh.write(original.replace(old, new))
        try:
            for profile in profiles:
                status, count, failed = evaluate(sandbox, outdir, args.cargo, profile, expected)
                rows.append((mid, profile, status, count, ",".join(failed), model))
                print("mutate: %-26s %-7s %-12s %s" % (mid, profile, status, ",".join(failed)))
                if status != "killed":
                    bad += 1
        finally:
            with open(path, "w", newline="") as fh:
                fh.write(original)
    write_rows(outdir, rows)
    killed = sum(1 for r in rows if r[2] == "killed")
    print("mutate: %d mutants x %d profiles: %d killed by an expected test, %d not" % (
        len(mutants), len(profiles), killed, bad))
    return 0 if bad == 0 else 1


def write_rows(outdir, rows):
    with open(os.path.join(outdir, "mutations.tsv"), "w", newline="\n") as fh:
        fh.write("mutant\tprofile\tstatus\ttests_run\tfailed_tests\tmodel\n")
        for r in rows:
            fh.write("\t".join(str(c) for c in r) + "\n")


def refuse_outdir(outdir):
    real = os.path.realpath(outdir)
    if os.path.exists(real):
        return "--outdir already exists; give a new directory"
    pk = os.path.realpath(PACKET)
    if real == pk or real.startswith(pk + os.sep):
        return "--outdir lies inside the packet"
    return None


def subrun(me, args, spec=None):
    cmd = [sys.executable, "-I", me] + args
    if spec is not None:
        cmd += ["--spec", spec]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=3600)


def selftest(args):
    """Controls: each must fail (or succeed) for the stated reason, after a clean baseline."""
    os.makedirs(args.outdir)
    me = os.path.abspath(__file__)
    work = args.outdir
    common = ["--repo-root", args.repo_root, "--profiles", "debug"]

    def spec(name, items):
        path = os.path.join(work, name + ".json")
        with open(path, "w") as fh:
            json.dump(items, fh)
        return path

    ok_mutant = ["C-kill", LIB, "p.push(0x80 | 3);", "p.push(0x80 | 2);", [P_ORACLE], "control"]
    controls = []
    # 0. a normal killable mutant with a clean baseline must exit 0
    r = subrun(me, common + ["--outdir", os.path.join(work, "c0")], spec("c0", [ok_mutant]))
    controls.append(("clean baseline + killable mutant exits 0", r.returncode == 0 and "1 killed" in r.stdout, r))
    # 1. an equivalent mutant (same bytes) survives -> non-zero and reported
    eq = ["C-equivalent", LIB, "p.push(0x80 | 3);", "p.push(0x83);", [P_ORACLE], "control"]
    r = subrun(me, common + ["--outdir", os.path.join(work, "c1")], spec("c1", [eq]))
    controls.append(("surviving mutant gives non-zero", r.returncode == 1 and "survived" in r.stdout, r))
    # 2. a mutant that does not compile is a build error, never a kill
    bad = ["C-syntax", LIB, "p.push(0x80 | 3);", "p.push(0x80 | 3)", [P_ORACLE], "control"]
    r = subrun(me, common + ["--outdir", os.path.join(work, "c2")], spec("c2", [bad]))
    controls.append(("compile error is not a kill", r.returncode == 1 and "build-error" in r.stdout, r))
    # 3. a failure in a test other than the expected one is not accepted as the kill
    wrong = ["C-wrong-test", LIB, "p.push(0x80 | 3);", "p.push(0x80 | 2);", ["tag_matches_oracle"], "control"]
    r = subrun(me, common + ["--outdir", os.path.join(work, "c3")], spec("c3", [wrong]))
    controls.append(("failure in the wrong test is not a kill", r.returncode == 1 and "wrong-test" in r.stdout, r))
    # 4. a pattern that is not present exactly once is rejected
    missing = ["C-missing", LIB, "this text is not in lib.rs", "x", [P_ORACLE], "control"]
    r = subrun(me, common + ["--outdir", os.path.join(work, "c4")], spec("c4", [missing]))
    controls.append(("missing pattern is rejected", r.returncode == 1 and "bad-pattern" in r.stdout, r))
    # 5. a broken baseline stops the run before any mutant is counted
    breaker = os.path.join(work, "broken-repo")
    for d in SRC_DIRS:
        shutil.copytree(os.path.join(args.repo_root, "src", d), os.path.join(breaker, "src", d),
                        ignore=shutil.ignore_patterns("target"))
    lib = os.path.join(breaker, "src", LIB)
    with open(lib, newline="") as fh:
        text = fh.read()
    with open(lib, "w", newline="") as fh:
        fh.write(text.replace("p.push(0x80 | 3);", "p.push(0x80 | 2);"))
    r = subrun(me, ["--repo-root", breaker, "--profiles", "debug", "--outdir", os.path.join(work, "c5")], spec("c5", [ok_mutant]))
    controls.append(("broken baseline aborts non-zero", r.returncode == 1 and "baseline" in r.stdout and "killed by an expected" not in r.stdout, r))
    # 6. cargo that stops working after the baseline must give an error, not 72/72 kills
    stub = os.path.join(work, "flaky-cargo.py")
    counter = os.path.join(work, "flaky-count")
    with open(stub, "w") as fh:
        fh.write("#!%s\nimport os, subprocess, sys\n" % sys.executable
                 + "p = %r\n" % counter
                 + "n = int(open(p).read()) if os.path.exists(p) else 0\n"
                 + "open(p, 'w').write(str(n + 1))\n"
                 + "if n >= 2:\n    sys.stderr.write('simulated compiler I/O error\\n')\n    sys.exit(101)\n"
                 + "sys.exit(subprocess.call(['cargo'] + sys.argv[1:]))\n")
    os.chmod(stub, 0o755)
    r = subrun(me, common + ["--cargo", stub, "--outdir", os.path.join(work, "c6")], spec("c6", [ok_mutant]))
    controls.append(("cargo failing after baseline is not a kill", r.returncode == 1 and "build-error" in r.stdout and "1 killed" not in r.stdout, r))
    # 7. outdir guards
    r = subrun(me, ["--repo-root", args.repo_root])
    controls.append(("missing --outdir refused (exit 2)", r.returncode == 2, r))
    r = subrun(me, ["--repo-root", args.repo_root, "--outdir", work])
    controls.append(("existing --outdir refused (exit 4)", r.returncode == 4, r))
    r = subrun(me, ["--repo-root", args.repo_root, "--outdir", os.path.join(PACKET, "new-out")])
    controls.append(("--outdir inside packet refused (exit 4)", r.returncode == 4, r))
    good = 0
    for name, ok, r in controls:
        say("selftest: %-48s %s" % (name, "ok" if ok else "FAILED (exit %d)" % r.returncode))
        if not ok:
            say("   stdout: " + r.stdout.strip()[-300:].replace("\n", " | "))
            say("   stderr: " + r.stderr.strip()[-300:].replace("\n", " | "))
        good += ok
    say("selftest: %d/%d controls behaved as expected" % (good, len(controls)))
    return 0 if good == len(controls) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--repo-root", default=os.path.normpath(os.path.join(PACKET, "..", "..", "..")))
    ap.add_argument("--profiles", default="debug,release")
    ap.add_argument("--cargo", default="cargo")
    ap.add_argument("--spec", help="JSON list of mutants (selftest use)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    why = refuse_outdir(args.outdir)
    if why:
        print("mutate: " + why, file=sys.stderr)
        return 4
    try:
        if args.selftest:
            rc = selftest(args)
            with open(os.path.join(args.outdir, "selftest.txt"), "w", newline="\n") as fh:
                fh.write("\n".join(LOG) + "\n")
            return rc
        mutants = MUTANTS
        if args.spec:
            with open(args.spec) as fh:
                mutants = [tuple(m) for m in json.load(fh)]
        return run(args, mutants)
    except Env as exc:
        print("mutate: environment error: %s" % exc, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
