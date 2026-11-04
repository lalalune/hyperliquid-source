#!/usr/bin/env python3
"""Unit tests for packet #276's verifier. Tamper controls run FIRST:
each must make the verifier fail; a clean temp copy must pass.
Temp layout mirrors the worktree (research/work-items/<slug>/,
tools/, tests/) and reuses the real binary by symlink, not by copy.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUG = "RE-001-node115-lu-bintableinit-caller-8sites"
PKG = os.path.join(ROOT, "research", "work-items", SLUG)
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_bintableinit_caller_8sites.py")
TESTS = os.path.join(ROOT, "tests", "test_node115_lu_bintableinit_caller_8sites.py")

PASSED = 0
FAILED = 0


def check(cond, msg):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print("ok -", msg)
    else:
        FAILED += 1
        print("FAILED -", msg)


def make_temp():
    tmp = tempfile.mkdtemp(prefix="hl276-")
    pkg = os.path.join(tmp, "research", "work-items", SLUG)
    os.makedirs(pkg)
    for f in os.listdir(PKG):
        shutil.copy(os.path.join(PKG, f), os.path.join(pkg, f))
    tools = os.path.join(tmp, "tools")
    tests = os.path.join(tmp, "tests")
    os.makedirs(tools)
    os.makedirs(tests)
    shutil.copy(VERIFIER, os.path.join(tools, os.path.basename(VERIFIER)))
    shutil.copy(TESTS, os.path.join(tests, os.path.basename(TESTS)))
    os.symlink(os.path.join(ROOT, "artifacts"),
                os.path.join(tmp, "artifacts"))
    return tmp, pkg


def run_verifier(tmp, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    r = subprocess.run([sys.executable,
                        os.path.join(tmp, "tools",
                                     os.path.basename(VERIFIER))],
                       capture_output=True, text=True, env=env)
    return r


def test_tamper_hex_flip():
    tmp, pkg = make_temp()
    try:
        p = os.path.join(pkg, "bintableinit_caller_8sites.hex")
        b = bytearray(open(p, "rb").read())
        b[100] ^= 0xFF
        open(p, "wb").write(bytes(b))
        r = run_verifier(tmp)
        check(r.returncode != 0, "tamper: hex flip fails verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_strict_count():
    tmp, pkg = make_temp()
    try:
        p = os.path.join(pkg, "records.json")
        rec = json.load(open(p))
        rec["exhibits"][0]["strict"] = 1178
        json.dump(rec, open(p, "w"))
        r = run_verifier(tmp)
        check(r.returncode != 0, "tamper: strict-count change fails verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_call_site_list():
    tmp, pkg = make_temp()
    try:
        p = os.path.join(pkg, "records.json")
        rec = json.load(open(p))
        rec["call_census"]["bin_table_init"]["sites"] = \
            rec["call_census"]["bin_table_init"]["sites"][:-1]
        json.dump(rec, open(p, "w"))
        r = run_verifier(tmp)
        check(r.returncode != 0, "tamper: call-site list change fails verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_injected_overlap():
    tmp, pkg = make_temp()
    try:
        prior = tempfile.mkdtemp(prefix="hl276-prior-")
        rec = {"exhibits": [{"name": "fake",
                             "range": "0x63c9c80..0x63c9d00"}]}
        json.dump(rec, open(os.path.join(prior, "records.json"), "w"))
        r = run_verifier(tmp, {"HL276_PRIOR_ROOTS": prior})
        check(r.returncode != 0, "tamper: injected overlap fails verifier")
        shutil.rmtree(prior, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_temp_copy():
    tmp, pkg = make_temp()
    try:
        r = run_verifier(tmp)
        check(r.returncode == 0, "clean temp copy passes verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_regeneration_objdump():
    tmp, pkg = make_temp()
    try:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=0x63c9c80",
             "--stop-address=0x63cb146",
             os.path.join(ROOT, "artifacts", "node", "115", "hl-node")],
            capture_output=True, text=True)
        fresh = [l for l in out.stdout.splitlines()
                 if not l.startswith("artifacts/") and "file format" not in l
                 and "Disassembly" not in l and l.strip()]
        stored = [l for l in
                  open(os.path.join(pkg, "bintableinit_caller_8sites.objdump.txt")).read().splitlines()
                  if not l.startswith("artifacts/") and "file format" not in l
                  and "Disassembly" not in l and l.strip()]
        check(fresh == stored, "regeneration: objdump matches stored exhibit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_regeneration_hex():
    data = open(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"), "rb").read()
    stored = open(os.path.join(PKG, "bintableinit_caller_8sites.hex"), "rb").read()
    check(stored == data[0x63c9c80 - 0x1000:0x63cb146 - 0x1000],
          "regeneration: hex equals binary slice")


def test_independent_strict_recount():
    import re
    lines = open(os.path.join(PKG, "bintableinit_caller_8sites.objdump.txt")).read().splitlines()
    strict = sum(1 for l in lines
                 if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l))
    check(strict == 1179, "independent strict recount == 1179, got %d" % strict)


def test_call_census_independent():
    import re
    lines = open(os.path.join(PKG, "bintableinit_caller_8sites.objdump.txt")).read().splitlines()
    calls = [l for l in lines if re.search(r"\tcall\s+[0-9a-f]+", l)]
    bti = [l for l in calls if "63d9880" in l]
    miss = [l for l in calls if "63d9700" in l]
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check(len(calls) == 21 and len(bti) == 8 and len(miss) == 8 and len(rets) == 0,
          "independent census: 21 calls, 8 bti, 8 miss, 0 ret")


if __name__ == "__main__":
    # Tamper controls FIRST.
    test_tamper_hex_flip()
    test_tamper_strict_count()
    test_tamper_call_site_list()
    test_tamper_injected_overlap()
    test_clean_temp_copy()
    test_regeneration_objdump()
    test_regeneration_hex()
    test_independent_strict_recount()
    test_call_census_independent()
    print("%d passed, %d failed" % (PASSED, FAILED))
    sys.exit(0 if FAILED == 0 else 1)
