#!/usr/bin/env python3
"""Unit tests for the node115 lu bintableinit caller walk rsp 4sites
verifier. Tamper controls run first: each must make the verifier fail.
Then a clean temp copy must pass, plus regeneration and independent
recounts. The temp copy symlinks the 105MB binary instead of copying it;
the verifier only reads bytes, so this is faithful and fast. Temp layout
mirrors the repo (tools/, tests/, research/work-items/<slug>/,
artifacts/node/115/) so MANIFEST's ../../../ references resolve.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
VERIFIER = os.path.join(ROOT, "tools",
                        "node115_lu_bintableinit_caller_walk_rsp_4sites.py")
TESTS_FILE = os.path.join(
    ROOT, "tests", "test_node115_lu_bintableinit_caller_walk_rsp_4sites.py")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("PASS: %s" % name)
    else:
        FAIL += 1
        print("FAIL: %s %s" % (name, detail))


def make_temp_copy():
    tmp = tempfile.mkdtemp(prefix="hl281test-")
    tools = os.path.join(tmp, "tools")
    tests = os.path.join(tmp, "tests")
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    art = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(tools)
    os.makedirs(tests)
    os.makedirs(pkt)
    os.makedirs(art)
    shutil.copy(VERIFIER, tools)
    shutil.copy(TESTS_FILE, tests)
    for name in os.listdir(PACKET):
        shutil.copy(os.path.join(PACKET, name), pkt)
    os.symlink(BINARY, os.path.join(art, "hl-node"))
    return tmp


def run_verifier(tmp):
    v = os.path.join(tmp, "tools",
                     "node115_lu_bintableinit_caller_walk_rsp_4sites.py")
    r = subprocess.run([sys.executable, v],
                       capture_output=True, text=True, timeout=900)
    return r.returncode, r.stdout


def test_tamper_hex_flip():
    tmp = make_temp_copy()
    try:
        p = os.path.join(tmp, "research", "work-items", SLUG,
                         "bintableinit_caller_walk_rsp_4sites.hex")
        b = bytearray(open(p, "rb").read())
        b[100] ^= 0xFF
        open(p, "wb").write(bytes(b))
        rc, _ = run_verifier(tmp)
        check("tamper hex flip fails verifier", rc != 0, rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_strict_count():
    tmp = make_temp_copy()
    try:
        p = os.path.join(tmp, "research", "work-items", SLUG,
                         "bintableinit_caller_walk_rsp_4sites.objdump.txt")
        lines = open(p).read().splitlines(True)
        strict_re = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
        for i, l in enumerate(lines):
            if strict_re.match(l):
                del lines[i]
                break
        open(p, "w").write("".join(lines))
        rc, _ = run_verifier(tmp)
        check("tamper strict-count fails verifier", rc != 0, rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_call_site():
    tmp = make_temp_copy()
    try:
        p = os.path.join(tmp, "research", "work-items", SLUG, "records.json")
        rec = json.load(open(p))
        rec["bin_table_init_sites"][0]["site"] = "0x63c8fc7"
        json.dump(rec, open(p, "w"))
        rc, _ = run_verifier(tmp)
        check("tamper call-site fails verifier", rc != 0, rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_injected_overlap():
    tmp = make_temp_copy()
    try:
        p = os.path.join(tmp, "research", "work-items", SLUG, "records.json")
        rec = json.load(open(p))
        # packet #280's window: must collide with prior claims
        rec["exhibits"].append({"bytes": 2228, "calls": 23,
                                "name": "injected",
                                "range": "0x63cb150..0x63cba04",
                                "rets": 0, "strict": 469})
        json.dump(rec, open(p, "w"))
        rc, _ = run_verifier(tmp)
        check("tamper injected overlap fails verifier", rc != 0, rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_copy_passes():
    tmp = make_temp_copy()
    try:
        rc, out = run_verifier(tmp)
        check("clean temp copy passes", rc == 0, out[-500:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_regenerate_hex():
    data = open(BINARY, "rb").read()
    start, end = 0x63C8D60, 0x63C94FC
    regen = data[start - 0x1000:end - 0x1000]
    exhibit = open(os.path.join(
        PACKET, "bintableinit_caller_walk_rsp_4sites.hex"), "rb").read()
    check("regenerate hex", regen == exhibit)


def test_regenerate_objdump_strict():
    r = subprocess.run(["objdump", "-d", "--start-address=0x63c8d60",
                        "--stop-address=0x63c94fc", BINARY],
                       capture_output=True, text=True, check=True)
    strict_re = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    n = sum(1 for l in r.stdout.splitlines() if strict_re.match(l))
    check("regenerate objdump strict", n == 411, n)


def test_independent_census():
    text = open(os.path.join(
        PACKET, "bintableinit_caller_walk_rsp_4sites.objdump.txt")).read()
    strict_re = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    calls = len(re.findall(r"\tcall\s", text))
    # count call lines only among strict lines (call appears only there)
    strict = [l for l in text.splitlines() if strict_re.match(l)]
    ncalls = sum(1 for l in strict if "\tcall\t" in l or "\tcall " in l)
    nbti = sum(1 for l in strict if "\tcall" in l and "63d9880" in l)
    nmiss = sum(1 for l in strict if "\tcall" in l and "63d9700" in l)
    nret = sum(1 for l in strict if re.search(r"\tret\s*$", l))
    check("independent census",
          len(strict) == 411 and ncalls == 14 and nbti == 4 and
          nmiss == 4 and nret == 0,
          (len(strict), ncalls, nbti, nmiss, nret))


def test_manifest_temp_copy():
    tmp = make_temp_copy()
    try:
        pkt = os.path.join(tmp, "research", "work-items", SLUG)
        r = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                           cwd=pkt, capture_output=True, text=True)
        check("manifest temp copy", r.returncode == 0, r.stdout[-300:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_self_exclusion():
    # The temp copy contains ONLY this packet in its merged tree, yet the
    # verifier must pass: its own window must not self-collide and its
    # own slug must not self-collide. (Covered by clean-copy pass, but
    # asserted explicitly here with the verifier's own output.)
    tmp = make_temp_copy()
    try:
        rc, out = run_verifier(tmp)
        check("self exclusion", rc == 0 and "PASS: disjointness" in out
              and "PASS: slug unique" in out, out[-500:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_records_roundtrip():
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    ok = (rec["fde"]["bytes"] == 1948 and
          rec["exhibits"][0]["range"] == "0x63c8d60..0x63c94fc" and
          len(rec["bin_table_init_sites"]) == 4 and
          len(rec["lu_miss_sites"]) == 4 and
          rec["prior_pointer_verified"]["verified_bytes"] == 1948)
    check("records roundtrip", ok)


def main():
    test_tamper_hex_flip()
    test_tamper_strict_count()
    test_tamper_call_site()
    test_tamper_injected_overlap()
    test_clean_copy_passes()
    test_regenerate_hex()
    test_regenerate_objdump_strict()
    test_independent_census()
    test_manifest_temp_copy()
    test_self_exclusion()
    test_records_roundtrip()
    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
