#!/usr/bin/env python3
"""Tests for RE-001-node115-lu-bintableinit-caller-6sites.

Custom runner (not unittest TestCase): run directly with
`python3 tests/test_node115_lu_bintableinit_caller_6sites.py`.
Tamper controls run FIRST; each must make the verifier fail.
Exits 0 iff all 9 tests pass. The binary is reused by symlink,
never copied; temp layouts include the tools AND tests files.
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
SLUG = "RE-001-node115-lu-bintableinit-caller-6sites"
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
VERIFIER = os.path.join(ROOT, "tools",
                        "node115_lu_bintableinit_caller_6sites.py")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

passed = []
failed = []


def check(name, ok, detail=""):
    (passed if ok else failed).append(name)
    print(("PASS " if ok else "FAIL ") + name
          + ((" | " + str(detail)) if detail else ""))


def make_temp():
    tmp = tempfile.mkdtemp(prefix="hl277test-")
    tools = os.path.join(tmp, "tools")
    tests = os.path.join(tmp, "tests")
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    art = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(tools)
    os.makedirs(tests)
    os.makedirs(pkt)
    os.makedirs(art)
    shutil.copy(VERIFIER, tools)
    shutil.copy(os.path.abspath(__file__), tests)
    for name in os.listdir(PACKET):
        shutil.copy(os.path.join(PACKET, name), pkt)
    os.symlink(BINARY, os.path.join(art, "hl-node"))
    return tmp, os.path.join(tools,
                             "node115_lu_bintableinit_caller_6sites.py")


def run_verifier(verifier, env_extra=None):
    env = dict(os.environ)
    env.pop("HL277_PRIOR_ROOTS", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([sys.executable, verifier],
                          capture_output=True, text=True, env=env)
    return proc.returncode


def main():
    # ---- tamper controls FIRST ----
    tmp, verifier = make_temp()
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    small_roots = {"HL277_PRIOR_ROOTS": os.path.join(
        tmp, "research", "work-items")}

    # 1. hex flip
    hex_path = os.path.join(pkt, "bintableinit_caller_6sites.hex")
    data = bytearray(open(hex_path, "rb").read())
    data[100] ^= 0xFF
    open(hex_path, "wb").write(bytes(data))
    check("tamper-hex-flip-fails",
          run_verifier(verifier, small_roots) != 0)

    # 2. strict-count change
    shutil.rmtree(tmp)
    tmp, verifier = make_temp()
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    small_roots = {"HL277_PRIOR_ROOTS": os.path.join(
        tmp, "research", "work-items")}
    rec_path = os.path.join(pkt, "records.json")
    rec = json.load(open(rec_path))
    rec["exhibits"][0]["strict"] = 881
    json.dump(rec, open(rec_path, "w"))
    check("tamper-strict-count-fails",
          run_verifier(verifier, small_roots) != 0)

    # 3. call-site list change
    shutil.rmtree(tmp)
    tmp, verifier = make_temp()
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    small_roots = {"HL277_PRIOR_ROOTS": os.path.join(
        tmp, "research", "work-items")}
    rec_path = os.path.join(pkt, "records.json")
    rec = json.load(open(rec_path))
    rec["bin_table_init_sites"][0]["site"] = "0x63cf131"
    json.dump(rec, open(rec_path, "w"))
    check("tamper-call-site-fails",
          run_verifier(verifier, small_roots) != 0)

    # 4. injected overlap via HL277_PRIOR_ROOTS
    shutil.rmtree(tmp)
    tmp, verifier = make_temp()
    fake_root = os.path.join(tmp, "fake", "research", "work-items")
    fake_pkt = os.path.join(fake_root, "FAKE-prior")
    os.makedirs(fake_pkt)
    json.dump({"exhibits": [{"name": "x",
                             "range": "0x63ce900..0x63cea00"}]},
              open(os.path.join(fake_pkt, "records.json"), "w"))
    check("tamper-overlap-fails",
          run_verifier(verifier, {"HL277_PRIOR_ROOTS": fake_root}) != 0)

    # ---- clean temp copy passes (full real prior scan) ----
    shutil.rmtree(tmp)
    tmp, verifier = make_temp()
    check("clean-temp-copy-passes", run_verifier(verifier) == 0)

    # ---- regeneration comparison (objdump header stripped) ----
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    proc = subprocess.run(
        ["objdump", "-d", "--start-address=0x63ce8c0",
         "--stop-address=0x63cf8bc", BINARY],
        capture_output=True, text=True)
    regen = [l for l in proc.stdout.splitlines()
             if "file format" not in l]
    stored = [l for l in open(os.path.join(
        pkt, "bintableinit_caller_6sites.objdump.txt")).read().splitlines()
        if "file format" not in l]
    check("regeneration-comparison", regen == stored,
          "regen %d stored %d" % (len(regen), len(stored)))

    # ---- hex vs binary slice ----
    blob = open(BINARY, "rb").read()
    hex_bytes = open(os.path.join(
        pkt, "bintableinit_caller_6sites.hex"), "rb").read()
    check("hex-vs-binary-slice",
          hex_bytes == blob[0x63CE8C0 - 0x1000:0x63CF8BC - 0x1000])

    # ---- independent strict recount ----
    lines = [l for l in open(os.path.join(
        pkt, "bintableinit_caller_6sites.objdump.txt"))
        if STRICT_RE.match(l)]
    check("independent-strict-recount", len(lines) == 882, len(lines))

    # ---- independent call census ----
    calls = {}
    rets = 0
    for line in lines:
        if re.search(r"\tcall\s", line):
            m = re.search(r"\tcall\s+([0-9a-f]+)", line)
            tgt = m.group(1) if m else "?"
            calls[tgt] = calls.get(tgt, 0) + 1
        elif re.search(r"\tret\s*$", line):
            rets += 1
    check("independent-census",
          sum(calls.values()) == 22 and calls.get("63d9880") == 6
          and calls.get("63d9700") == 6 and rets == 1,
          "total %d bti %d miss %d ret %d"
          % (sum(calls.values()), calls.get("63d9880"),
             calls.get("63d9700"), rets))

    shutil.rmtree(tmp, ignore_errors=True)
    print("PASS: %d FAIL: %d" % (len(passed), len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
