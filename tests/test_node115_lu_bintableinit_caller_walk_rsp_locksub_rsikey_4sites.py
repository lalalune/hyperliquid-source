#!/usr/bin/env python3
"""Unit tests for the #286 packet verifier.

Run from the repository root:
    python3 tests/test_node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py
Exit 0 when every check passes. Tamper controls run FIRST: each tamper must
make the verifier fail; only then is the clean copy expected to pass.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
VERIFIER = os.path.join(
    ROOT, "tools", "node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py")
TESTS_FILE = os.path.join(
    ROOT, "tests", "test_node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
HEX_NAME = "bintableinit_caller_walk_rsp_locksub_rsikey_4sites.hex"
OBJ_NAME = "bintableinit_caller_walk_rsp_locksub_rsikey_4sites.objdump.txt"

checks = []


def check(name, ok, detail=""):
    checks.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else ""))


def run_verifier(cwd):
    return subprocess.run([sys.executable, VERIFIER if cwd == ROOT else
                           os.path.join(cwd, "tools", os.path.basename(VERIFIER))],
                          capture_output=True, text=True, cwd=cwd)


def make_temp_copy():
    tmp = tempfile.mkdtemp(prefix="hl286-test-")
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    os.makedirs(os.path.join(tmp, "tools"))
    os.makedirs(os.path.join(tmp, "tests"))
    os.makedirs(os.path.join(tmp, "artifacts", "node", "115"))
    shutil.copytree(PACKET, pkt)
    shutil.copy(VERIFIER, os.path.join(tmp, "tools", os.path.basename(VERIFIER)))
    shutil.copy(TESTS_FILE, os.path.join(tmp, "tests", os.path.basename(TESTS_FILE)))
    os.symlink(BINARY, os.path.join(tmp, "artifacts", "node", "115", "hl-node"))
    return tmp, pkt


def mutate_records(pkt, fn):
    path = os.path.join(pkt, "records.json")
    rec = json.load(open(path))
    fn(rec)
    json.dump(rec, open(path, "w"))


def main():
    # Tamper controls FIRST (each must fail the verifier).
    tmp, pkt = make_temp_copy()
    try:
        # 1. Hex flip.
        hp = os.path.join(pkt, HEX_NAME)
        raw = bytearray(open(hp, "rb").read())
        raw[100] ^= 0xFF
        open(hp, "wb").write(bytes(raw))
        r = run_verifier(tmp)
        check("tamper hex flip fails", r.returncode != 0)
        shutil.rmtree(tmp)
        tmp, pkt = make_temp_copy()
        # 2. Strict-count change via parsed JSON.
        mutate_records(pkt, lambda rec: rec["window"].__setitem__("strict", 379))
        r = run_verifier(tmp)
        check("tamper strict-count change fails", r.returncode != 0)
        shutil.rmtree(tmp)
        tmp, pkt = make_temp_copy()
        # 3. Call-site change via parsed JSON.
        mutate_records(pkt, lambda rec: rec["bin_table_init_sites"][0].__setitem__(
            "site", "0x63d5a97"))
        r = run_verifier(tmp)
        check("tamper call-site change fails", r.returncode != 0)
        shutil.rmtree(tmp)
        tmp, pkt = make_temp_copy()
        # 4. Injected overlap via parsed JSON.
        def inject(rec):
            rec["exhibits"].append({"name": "injected",
                                    "range": "0x63d5940..0x63d6000"})
        mutate_records(pkt, inject)
        r = run_verifier(tmp)
        check("tamper injected overlap fails", r.returncode != 0)
        shutil.rmtree(tmp)
        # Clean temp copy passes.
        tmp, pkt = make_temp_copy()
        r = run_verifier(tmp)
        check("clean temp copy passes", r.returncode == 0,
              r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr[-200:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Verifier passes on the real tree.
    r = run_verifier(ROOT)
    check("verifier passes on real tree", r.returncode == 0,
          r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr[-200:])

    # Regeneration: hex slice and targeted objdump recount.
    data = open(BINARY, "rb").read()
    check("regenerated hex bytes",
          data[0x63D5940 - 0x1000:0x63D5940 - 0x1000 + 1820] ==
          open(os.path.join(PACKET, HEX_NAME), "rb").read())
    regen = subprocess.run(
        ["objdump", "-d", "--start-address=0x63d5940", "--stop-address=0x63d605c",
         BINARY], capture_output=True, text=True, cwd=ROOT)
    strict_re = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    regen_strict = [l for l in regen.stdout.splitlines() if strict_re.match(l)]
    check("regenerated objdump strict", len(regen_strict) == 378,
          f"{len(regen_strict)} lines")

    # Independent recounts from the packet objdump exhibit.
    lines = open(os.path.join(PACKET, OBJ_NAME)).read().splitlines()
    check("independent strict recount",
          sum(1 for l in lines if strict_re.match(l)) == 378)
    call_lines = [l for l in lines if re.search(r"\tcall\s", l)]
    check("independent call recount", len(call_lines) == 9)
    check("independent bti recount",
          sum(1 for l in call_lines if "63d9880" in l) == 4)
    check("independent miss recount",
          sum(1 for l in call_lines if "63d9700" in l) == 4)
    check("independent locksub recount",
          sum(1 for l in lines if re.search(r"\tlock sub\s", l)) == 1)

    failed = [n for n, ok in checks if not ok]
    print(f"PASS count: {len(checks) - len(failed)}, FAIL count: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
