#!/usr/bin/env python3
"""Unit tests for the #280 verifier.

Tamper controls run FIRST: each tamper must make the verifier fail.
Then a clean temp copy must pass, plus regeneration and recount checks.
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
PACKET = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-4sites-walk")
VERIFIER = os.path.join(
    ROOT, "tools", "node115_lu_bintableinit_caller_walk_4sites.py")
PACKET_REL = os.path.join(
    "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-4sites-walk")

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name} {detail}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def build_tmp():
    tmp = tempfile.mkdtemp(prefix="hl280test-")
    pdir = os.path.join(tmp, PACKET_REL)
    os.makedirs(pdir)
    for f in os.listdir(PACKET):
        shutil.copy(os.path.join(PACKET, f), os.path.join(pdir, f))
    tdir = os.path.join(tmp, "tools")
    os.makedirs(tdir)
    shutil.copy(VERIFIER, os.path.join(
        tdir, "node115_lu_bintableinit_caller_walk_4sites.py"))
    sdir = os.path.join(tmp, "tests")
    os.makedirs(sdir)
    shutil.copy(os.path.abspath(__file__), os.path.join(
        sdir, "test_node115_lu_bintableinit_caller_walk_4sites.py"))
    adir = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(adir)
    os.symlink(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"),
                os.path.join(adir, "hl-node"))
    return tmp


def run_verifier(tmp):
    v = os.path.join(tmp, "tools",
                     "node115_lu_bintableinit_caller_walk_4sites.py")
    r = subprocess.run([sys.executable, v], capture_output=True, text=True)
    return r.returncode


def main():
    # --- tamper controls first ---
    tmp = build_tmp()
    try:
        pdir = os.path.join(tmp, PACKET_REL)
        # 1. hex flip
        hp = os.path.join(pdir, "bintableinit_caller_walk_4sites.hex")
        b = bytearray(open(hp, "rb").read())
        b[100] ^= 0xFF
        open(hp, "wb").write(bytes(b))
        check("tamper hex flip fails verifier", run_verifier(tmp) != 0)
        shutil.rmtree(tmp)
        tmp = build_tmp()
        pdir = os.path.join(tmp, PACKET_REL)
        # 2. strict-count change in records
        rp = os.path.join(pdir, "records.json")
        rec = json.load(open(rp))
        rec["fde"]["strict"] = 470
        json.dump(rec, open(rp, "w"))
        check("tamper strict-count fails verifier", run_verifier(tmp) != 0)
        shutil.rmtree(tmp)
        tmp = build_tmp()
        pdir = os.path.join(tmp, PACKET_REL)
        # 3. call-site change in records
        rp = os.path.join(pdir, "records.json")
        rec = json.load(open(rp))
        rec["bin_table_init_sites"][0]["site"] = "0x63cb549"
        json.dump(rec, open(rp, "w"))
        check("tamper call-site fails verifier", run_verifier(tmp) != 0)
        shutil.rmtree(tmp)
        tmp = build_tmp()
        pdir = os.path.join(tmp, PACKET_REL)
        # 4. injected overlap: fake prior record overlapping our window
        fake_dir = os.path.join(tmp, "research", "work-items",
                                "RE-001-fake-overlap")
        os.makedirs(fake_dir)
        json.dump({"exhibits": [{"name": "fake", "range": "0x63cb200..0x63cb300"}]},
                  open(os.path.join(fake_dir, "records.json"), "w"))
        check("tamper injected overlap fails verifier",
              run_verifier(tmp) != 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- clean temp copy passes ---
    tmp = build_tmp()
    try:
        check("clean temp copy passes verifier", run_verifier(tmp) == 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- regeneration + independent recounts ---
    txt = open(os.path.join(
        PACKET, "bintableinit_caller_walk_4sites.objdump.txt")).read()
    lines = txt.splitlines()
    strict = [l for l in lines
              if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
    check("independent strict recount", len(strict) == 469,
          f"got {len(strict)}")
    calls = [l for l in strict if re.search(r"\tcall\s", l)]
    check("independent call recount", len(calls) == 23,
          f"got {len(calls)}")
    bti = [l for l in calls if "63d9880" in l]
    check("independent bti recount", len(bti) == 4, f"got {len(bti)}")
    miss = [l for l in calls if "63d9700" in l]
    check("independent lu-miss recount", len(miss) == 4,
          f"got {len(miss)}")
    rets = [l for l in strict if re.search(r"\tret\s*$", l)]
    check("independent ret recount", len(rets) == 0)
    node = open(os.path.join(ROOT, "artifacts", "node", "115",
                             "hl-node"), "rb").read()
    raw = open(os.path.join(
        PACKET, "bintableinit_caller_walk_4sites.hex"), "rb").read()
    check("regeneration exhibit bytes",
          raw == node[0x63CB150 - 0x1000:0x63CB150 - 0x1000 + 2228])

    print(f"PASS count: {PASS}, FAIL count: {FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
