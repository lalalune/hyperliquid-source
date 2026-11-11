#!/usr/bin/env python3
"""Standalone tests for packet #266 (RE-001 node-115, opt groups 16-20).

Custom runner (not unittest TestCases): run directly with python3.
Checks: objdump regeneration, independent strict recount, totals,
leaves-remaining, and tamper/layout controls. Tamper cases run FIRST
in spirit: they are separate checks that must fail the verifier;
a green verifier run is not trusted until they do.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET_DIR = os.path.join(ROOT, "research", "work-items",
                          "RE-001-node115-lu-opt-groups16-20-leaves")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_opt_groups16_20_leaves.py")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

passed = []
failed = []


def test(name, cond):
    (passed if cond else failed).append(name)
    print(("ok - " if cond else "FAIL - ") + name)


def run_verifier(env_extra=None, cwd=None):
    env = dict(os.environ)
    env.pop("HL266_PRIOR_ROOTS", None)
    if env_extra:
        env.update(env_extra)
    r = subprocess.run([sys.executable, VERIFIER], capture_output=True,
                       text=True, env=env, cwd=cwd)
    return r


def build_temp_layout(mutate=None):
    """Copy packet+tools into a temp tree mirroring repo layout."""
    tmp = tempfile.mkdtemp(prefix="hl266_test_")
    pkt = os.path.join(tmp, "research", "work-items",
                       "RE-001-node115-lu-opt-groups16-20-leaves")
    os.makedirs(pkt)
    for f in os.listdir(PACKET_DIR):
        shutil.copy2(os.path.join(PACKET_DIR, f), os.path.join(pkt, f))
    tools = os.path.join(tmp, "tools")
    os.makedirs(tools)
    shutil.copy2(VERIFIER, os.path.join(tools, os.path.basename(VERIFIER)))
    tests = os.path.join(tmp, "tests")
    os.makedirs(tests)
    shutil.copy2(os.path.abspath(__file__),
                 os.path.join(tests, os.path.basename(__file__)))
    if mutate:
        mutate(pkt)
    return tmp, pkt


def main():
    rec = json.load(open(os.path.join(PACKET_DIR, "records.json")))

    # Regeneration: objdump (strip first 2 header lines) == stored.
    for ex in rec["exhibits"]:
        s, e = ex["start"], ex["end"]
        r = subprocess.run(["objdump", "-d", "--start-address=%s" % hex(s),
                            "--stop-address=%s" % hex(e), BINARY],
                           capture_output=True, text=True)
        stored = open(os.path.join(PACKET_DIR, ex["objdump"])).read().splitlines()[2:]
        test("regen %s" % ex["name"], r.stdout.splitlines()[2:] == stored)

    # Independent strict recount.
    for ex in rec["exhibits"]:
        s, e = ex["start"], ex["end"]
        r = subprocess.run(["objdump", "-d", "--start-address=%s" % hex(s),
                            "--stop-address=%s" % hex(e), BINARY],
                           capture_output=True, text=True)
        n = sum(1 for l in r.stdout.splitlines() if STRICT_RE.match(l))
        test("strict %s" % ex["name"], n == ex["strict_instructions"])

    # Totals.
    test("total bytes", sum(e["size"] for e in rec["exhibits"]) == 2154)
    test("total bytes == records", sum(e["size"] for e in rec["exhibits"]) == rec["total_claimed_bytes"])
    test("total strict", sum(e["strict_instructions"] for e in rec["exhibits"]) == 597)
    test("total strict == records", sum(e["strict_instructions"] for e in rec["exhibits"]) == rec["total_strict_instructions"])
    test("leaves remaining", rec["leaves_remaining_after"] == 146)
    test("5 exhibits", len(rec["exhibits"]) == 5)
    test("exhibit count checks", all(e["size"] == e["end"] - e["start"] for e in rec["exhibits"]))

    # Tamper: hex flip must fail the verifier.
    def flip(pkt):
        p = os.path.join(pkt, "retain.hex")
        b = bytearray(open(p, "rb").read())
        b[0] ^= 0xFF
        open(p, "wb").write(bytes(b))
    tmp, _ = build_temp_layout(flip)
    r = run_verifier({"HL266_ROOT": tmp, "HL266_BINARY": BINARY})
    test("tamper hex-flip fails verifier", r.returncode != 0)
    shutil.rmtree(tmp, ignore_errors=True)

    # Tamper: strict-count change must fail the verifier.
    def strict_change(pkt):
        p = os.path.join(pkt, "records.json")
        d = json.load(open(p))
        d["exhibits"][0]["strict_instructions"] += 1
        json.dump(d, open(p, "w"))
    tmp, _ = build_temp_layout(strict_change)
    r = run_verifier({"HL266_ROOT": tmp, "HL266_BINARY": BINARY})
    test("tamper strict-count fails verifier", r.returncode != 0)
    shutil.rmtree(tmp, ignore_errors=True)

    # Tamper: injected overlap must fail the verifier and cite overlap.
    def make_overlap_root():
        root = tempfile.mkdtemp(prefix="hl266_prior_")
        d = os.path.join(root, "fake-prior")
        os.makedirs(d)
        json.dump({"exhibits": [{"name": "fake", "range": "0x6370480..0x6370490"}]},
                  open(os.path.join(d, "records.json"), "w"))
        return root
    prior = make_overlap_root()
    r = run_verifier({"HL266_PRIOR_ROOTS": prior})
    test("tamper injected-overlap fails verifier", r.returncode != 0)
    test("tamper injected-overlap cites overlap", "overlap" in (r.stdout + r.stderr).lower())
    shutil.rmtree(prior, ignore_errors=True)

    # Clean temp copy must pass.
    tmp, _ = build_temp_layout()
    r = run_verifier({"HL266_ROOT": tmp, "HL266_BINARY": BINARY})
    test("clean temp copy passes verifier", r.returncode == 0)
    if r.returncode != 0:
        print(r.stdout[-2000:])
    shutil.rmtree(tmp, ignore_errors=True)

    print("%d passed, %d failed" % (len(passed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
