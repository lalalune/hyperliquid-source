#!/usr/bin/env python3
"""Run the three checking tools against the failures a reviewer reproduced and keep the raw output.

Usage: python3 -I negative_controls.py <repository root> <hl-node> --outdir NEW_DIR

Each control makes one real fault, in a temporary copy (never in the repository tree), and runs the real tool
on it. A control passes when the tool refuses or exits non-zero in the way the fault calls for, and when the
inputs of the tool are byte-identical afterwards. Where a control is about a particular reason, the run must
also print that reason (so an unrelated refusal cannot make a control pass). Written to --outdir:
negative-controls.txt (command, exit status and the complete raw output of every run, then a summary). Exit
status 0 only if every control passes.

 1  verify_target.py, a wrong pin added to the pin file: the plain run must exit 1 (what the reviewer saw), the
    --selftest run must exit non-zero too (it used to report 10 of 10 damages rejected and exit 0, because the
    first error it saw was the pre-existing wrong pin), and the packet copy must be unchanged afterwards.
 2  verify_target.py without --outdir, with --outdir inside the packet, with a non-empty --outdir: refused.
 3  mutate.py with a stand-in `cargo` that lets the baseline pass and then fails like a broken toolchain
    (a process-spawn I/O error): no mutant may be counted as killed and the exit status must be non-zero, in two
    variants (the build fails; the build works and the test run produces no results).
 4  mutate.py with a harmless edit as the only mutant: reported as surviving, exit status non-zero.
 5  mutate.py without --outdir: refused, and no mutations.tsv appears in the packet.
 6  compare_trace.py with one row of the independent output damaged beforehand: the plain run must exit 1, the
    --selftest run must exit non-zero too (it used to reject 7 of 7 and exit 0), without --outdir: refused.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile

PACKET = "research/work-items/RE-008-node115-nested-certificate-decision"

FAKE_CARGO = r'''#!/usr/bin/env python3
import os, subprocess, sys
mode = os.environ["FAKE_CARGO_MODE"]
counter = os.environ["FAKE_CARGO_COUNTER"]
n = 0
if os.path.exists(counter):
    n = int(open(counter).read())
open(counter, "w").write(str(n + 1))
no_run = "--no-run" in sys.argv
# calls 0 and 1 are the baseline (build, then test run): they are real in both modes
real = n < 2 or (mode == "test-io-error" and no_run)
if real:
    sys.exit(subprocess.run([os.environ["FAKE_CARGO_REAL"]] + sys.argv[1:]).returncode)
sys.stderr.write("error: could not execute process `rustc -vV` (never executed)\n\nCaused by:\n  Input/output error (os error 5)\n")
sys.exit(101)
'''


def snapshot(path):
    import hashlib
    state = {}
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(root, name)
            with open(p, "rb") as f:
                state[os.path.relpath(p, path)] = hashlib.sha256(f.read()).hexdigest()
    return state


def main():
    args = sys.argv[1:]
    if len(args) < 4 or args[2] != "--outdir":
        sys.exit("usage: negative_controls.py <repository root> <hl-node> --outdir NEW_DIR")
    root, target, outdir = os.path.abspath(args[0]), os.path.abspath(args[1]), os.path.abspath(args[3])
    if os.path.exists(outdir) and os.listdir(outdir):
        sys.exit("--outdir must not exist yet or be empty")
    os.makedirs(outdir, exist_ok=True)
    packet = os.path.join(root, PACKET)
    py = [sys.executable, "-I"]
    tools = os.path.join(root, PACKET)
    log, summary = [], ["control\texpected\tgot\tverdict"]
    failures = 0

    def clean(s):
        return s.replace(target, "<target>").replace(root, "<root>").replace(tmp, "<tmp>")

    def run(name, cmd, env=None, expect_nonzero=True, must_print=None):
        """must_print: text the run has to print (stdout or stderr), so that the non-zero status is for the
        reason the control is about and not for an unrelated refusal."""
        nonlocal failures
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=env)
        shown = " ".join(os.path.basename(c) if os.path.sep in c and i == 0 else c for i, c in enumerate(cmd))
        log.append("==== %s\n$ %s\nexit status %d\n--- stdout\n%s--- stderr\n%s" % (name, clean(shown), r.returncode, clean(r.stdout), clean(r.stderr)))
        ok = (r.returncode != 0) == expect_nonzero
        if must_print is not None and must_print not in r.stdout + r.stderr:
            ok = False
            log.append("(expected the text %r in the output, not found)\n" % must_print)
        summary.append("%s\t%s\t%d\t%s" % (name, "non-zero" if expect_nonzero else "zero", r.returncode, "ok" if ok else "FAIL"))
        failures += 0 if ok else 1
        return r

    def check(name, cond, detail):
        nonlocal failures
        log.append("==== %s\n%s\n" % (name, detail))
        summary.append("%s\t%s\t%s\t%s" % (name, "true", str(cond).lower(), "ok" if cond else "FAIL"))
        failures += 0 if cond else 1

    with tempfile.TemporaryDirectory() as tmp:
        # ---- 1, 2: verify_target.py on a packet copy with a wrong pin --------------------------------------
        copy = os.path.join(tmp, "packet-copy")
        shutil.copytree(packet, copy)
        with open(os.path.join(copy, "pins.tsv"), "a", newline="\n") as f:
            f.write("decision\t0x595fd34\tmov 0x18(%rax),%rdx\n")
        before = snapshot(copy)
        v = py + [os.path.join(tools, "verify_target.py"), target, copy]
        run("verify-wrong-pin-plain", v + ["--outdir", os.path.join(tmp, "o1"), "--no-flips"], must_print="failures\t2")
        run("verify-wrong-pin-selftest", v + ["--outdir", os.path.join(tmp, "o2"), "--selftest"], must_print="baseline control FAILED")
        check("verify-packet-copy-unchanged-after-failing-runs", snapshot(copy) == before,
              "packet copy hashes equal before and after the two failing runs: %s" % (snapshot(copy) == before))
        run("verify-without-outdir", v, must_print="--outdir is required")
        run("verify-outdir-inside-packet", v + ["--outdir", os.path.join(copy, "out")], must_print="must not be the packet directory or inside it")
        os.makedirs(os.path.join(tmp, "nonempty"))
        with open(os.path.join(tmp, "nonempty", "x"), "w") as f:
            f.write("x")
        run("verify-outdir-not-empty", v + ["--outdir", os.path.join(tmp, "nonempty")], must_print="must not exist yet or be an empty directory")
        check("verify-packet-copy-unchanged-after-refusals", snapshot(copy) == before, "packet copy unchanged: %s" % (snapshot(copy) == before))

        # ---- 3: mutate.py with a stand-in cargo ------------------------------------------------------------
        real_cargo = shutil.which("cargo")
        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        fake = os.path.join(bindir, "cargo")
        with open(fake, "w") as f:
            f.write(FAKE_CARGO)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        packet_before = snapshot(packet)
        for mode in ("build-io-error", "test-io-error"):
            env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"], FAKE_CARGO_MODE=mode,
                       FAKE_CARGO_REAL=real_cargo, FAKE_CARGO_COUNTER=os.path.join(tmp, "counter-" + mode))
            od = os.path.join(tmp, "m-" + mode)
            run("mutate-fake-cargo-" + mode, py + [os.path.join(tools, "mutate.py"), root, "--outdir", od, "--only", "D01,E01"], env=env,
                must_print="ERROR build failed" if mode == "build-io-error" else "ERROR results missing")
            rows = open(os.path.join(od, "mutations.tsv")).read().splitlines()[1:] if os.path.exists(os.path.join(od, "mutations.tsv")) else []
            killed = [r for r in rows if r.split("\t")[5] == "yes"]
            check("mutate-fake-cargo-%s-counts-no-kill" % mode, len(rows) == 2 and not killed,
                  "mutations.tsv rows: %d, rows counted as killed: %d\n%s" % (len(rows), len(killed), "\n".join(rows)))

        # ---- 4: a harmless edit survives ---------------------------------------------------------------------
        od = os.path.join(tmp, "m-survivor")
        run("mutate-harmless-edit-survives", py + [os.path.join(tools, "mutate.py"), root, "--outdir", od, "--only", "Z00",
                                                  "--add-mutant", "Z00::lib.rs::pub mod verifier;::pub mod verifier; // harmless"],
            must_print="SURVIVED")
        rows = open(os.path.join(od, "mutations.tsv")).read().splitlines()[1:] if os.path.exists(os.path.join(od, "mutations.tsv")) else []
        check("mutate-harmless-edit-is-reported-as-surviving", len(rows) == 1 and rows[0].endswith("SURVIVED"), "\n".join(rows))

        # ---- 5: mutate.py without --outdir ---------------------------------------------------------------------
        run("mutate-without-outdir", py + [os.path.join(tools, "mutate.py"), root, "--only", "D01"], must_print="--outdir is required")
        check("repository-packet-unchanged-after-mutate-runs", snapshot(packet) == packet_before,
              "packet hashes equal before and after all mutate.py runs: %s" % (snapshot(packet) == packet_before))

        # ---- 6: compare_trace.py with a damaged independent output ----------------------------------------------
        cases = os.path.join(packet, "cases.tsv")
        good = os.path.join(packet, "independent-trace", "xcheck1", "outputs.tsv")
        lines = open(good, encoding="utf-8").read().split("\n")
        header = lines[0].split("\t")
        k = header.index("out_words")
        for i in range(1, len(lines)):
            cols = lines[i].split("\t")
            if len(cols) > k and cols[k] not in ("fwd", "-", ""):
                cols[k] = cols[k] + ":1"
                lines[i] = "\t".join(cols)
                damaged_id = cols[0]
                break
        os.makedirs(os.path.join(tmp, "damaged"))
        bad = os.path.join(tmp, "damaged", "outputs.tsv")
        with open(bad, "w", newline="\n", encoding="utf-8") as f:
            f.write("\n".join(lines))
        c = py + [os.path.join(tools, "independent-trace", "compare_trace.py"), cases, bad]
        run("compare-damaged-output-plain", c + ["--outdir", os.path.join(tmp, "results", "c1")], must_print="differing rows after normalization: 1")
        run("compare-damaged-output-selftest", c + ["--outdir", os.path.join(tmp, "results", "c2"), "--selftest"], must_print="baseline control FAILED")
        run("compare-without-outdir", c, must_print="--outdir")
        log.append("(the damaged row of the independent output is %s)\n" % damaged_id)

    with open(os.path.join(outdir, "negative-controls.txt"), "w", newline="\n") as f:
        f.write("\n".join(log) + "\n==== summary\n" + "\n".join(summary) + "\ncontrols failing: %d\n" % failures)
    print("\n".join(summary))
    print("controls failing: %d" % failures)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
