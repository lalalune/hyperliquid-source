#!/usr/bin/env python3
"""Unit tests for packet #275's verifier. Tamper controls run FIRST:
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
SLUG = "RE-001-node115-lu-bintableinit-caller"
PKG = os.path.join(ROOT, "research", "work-items", SLUG)
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_bintableinit_caller.py")
TESTS = os.path.join(ROOT, "tests", "test_node115_lu_bintableinit_caller.py")

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
    tmp = tempfile.mkdtemp(prefix="hl275-")
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
        p = os.path.join(pkg, "bintableinit_caller.hex")
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
        rec["exhibits"][0]["strict"] = 1014
        json.dump(rec, open(p, "w"))
        r = run_verifier(tmp)
        check(r.returncode != 0, "tamper: strict-count change fails verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_call_sites():
    tmp, pkg = make_temp()
    try:
        p = os.path.join(pkg, "records.json")
        rec = json.load(open(p))
        rec["call_census"]["bin_table_init"]["sites"] = \
            rec["call_census"]["bin_table_init"]["sites"][:9]
        json.dump(rec, open(p, "w"))
        r = run_verifier(tmp)
        check(r.returncode != 0, "tamper: call-site list change fails verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_injected_overlap():
    tmp, pkg = make_temp()
    try:
        prior = tempfile.mkdtemp(prefix="hl275-prior-")
        fake = {"exhibits": [{"name": "fake", "range": "0x63cba10..0x63cbb00"}]}
        json.dump(fake, open(os.path.join(prior, "records.json"), "w"))
        r = run_verifier(tmp, {"HL275_PRIOR_ROOTS": prior})
        check(r.returncode != 0, "tamper: injected overlap fails verifier")
        shutil.rmtree(prior, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_temp_copy():
    tmp, pkg = make_temp()
    try:
        r = run_verifier(tmp)
        check(r.returncode == 0,
              "clean temp copy passes verifier: " + r.stdout.strip().splitlines()[-1]
              if r.stdout.strip() else "clean temp copy passes verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_regeneration():
    # Regenerate the objdump exhibit and compare with the header lines
    # stripped (objdump embeds the input path in its header).
    import re
    out = subprocess.run(["objdump", "-d",
                          "--start-address=0x63cba10",
                          "--stop-address=0x63ccd22",
                          os.path.join(ROOT, "artifacts", "node", "115", "hl-node")],
                         capture_output=True, text=True)
    check(out.returncode == 0, "regeneration: objdump runs")
    stored = open(os.path.join(PKG, "bintableinit_caller.objdump.txt")).read()

    def strip(text):
        return [l for l in text.splitlines()
                if not l.startswith("artifacts/")
                and "file format" not in l]
    check(strip(out.stdout) == strip(stored),
          "regeneration: objdump matches stored exhibit (header stripped)")
    # Regenerate the hex exhibit from the binary slice.
    node = open(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"),
                "rb").read()
    regen = node[0x63CBA10 - 0x1000:0x63CBA10 - 0x1000 + 4882]
    stored_hex = open(os.path.join(PKG, "bintableinit_caller.hex"), "rb").read()
    check(regen == stored_hex, "regeneration: hex matches binary slice")


def test_strict_recount():
    import re
    lines = open(os.path.join(
        PKG, "bintableinit_caller.objdump.txt")).read().splitlines()
    strict = sum(1 for l in lines
                 if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l))
    check(strict == 1015, "independent strict recount == 1015, got %d" % strict)


if __name__ == "__main__":
    # Tamper controls FIRST.
    test_tamper_hex_flip()
    test_tamper_strict_count()
    test_tamper_call_sites()
    test_tamper_injected_overlap()
    test_clean_temp_copy()
    test_regeneration()
    test_strict_recount()
    print("%d passed, %d failed" % (PASSED, FAILED))
    sys.exit(0 if FAILED == 0 else 1)
