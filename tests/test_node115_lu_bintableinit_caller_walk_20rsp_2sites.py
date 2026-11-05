#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-bintableinit-caller-walk-20rsp packet.

Runs the TEMP copy's verifier (never the original path), plus independent
recounts and a regeneration comparison. Temp roots are workspace-adjacent
so the verifier's ROOT/../hl-wt-calls* prior glob resolves, and the binary
is a symlink, not a shim.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

WT = os.path.expanduser("~/workspace/hl-wt-calls292-115")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-20rsp"
SCRATCH = os.path.expanduser("~/workspace/scratch-hl292")
BIN = os.path.join(WT, "artifacts", "node", "115", "hl-node")
VERIFIER = "node115_lu_bintableinit_caller_walk_20rsp_2sites.py"
PACKET_FILES = ["README.md", "EVIDENCE.md", "records.json", "MANIFEST.sha256",
                "bintableinit_caller_walk_20rsp_2sites.hex",
                "bintableinit_caller_walk_20rsp_2sites.objdump.txt"]

fails = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else " :: " + str(detail)))
    if not ok:
        fails.append(name)


def make_temp():
    tmp = tempfile.mkdtemp(prefix="test-tmp-", dir=SCRATCH)
    os.makedirs(os.path.join(tmp, "tools"))
    shutil.copy(os.path.join(WT, "tools", VERIFIER), os.path.join(tmp, "tools", VERIFIER))
    pkt = os.path.join(tmp, "research", "work-items", SLUG)
    os.makedirs(pkt)
    for f in PACKET_FILES:
        shutil.copy(os.path.join(WT, "research", "work-items", SLUG, f),
                    os.path.join(pkt, f))
    art = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(art)
    os.symlink(BIN, os.path.join(art, "hl-node"))
    return tmp


def run_verifier(tmp):
    return subprocess.run([sys.executable, os.path.join(tmp, "tools", VERIFIER)],
                          capture_output=True, text=True).returncode


def tamper(name, fn):
    tmp = make_temp()
    try:
        fn(os.path.join(tmp, "research", "work-items", SLUG))
        rc = run_verifier(tmp)
        check("tamper fails: " + name, rc != 0, "exit %d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# clean temp copy passes
tmp = make_temp()
try:
    rc = run_verifier(tmp)
    check("clean temp verifier passes", rc == 0, "exit %d" % rc)
finally:
    shutil.rmtree(tmp, ignore_errors=True)


def flip_hex(pkt):
    p = os.path.join(pkt, "bintableinit_caller_walk_20rsp_2sites.hex")
    b = bytearray(open(p, "rb").read())
    b[100] ^= 0xFF
    open(p, "wb").write(bytes(b))


def strict_change(pkt):
    p = os.path.join(pkt, "records.json")
    r = json.load(open(p))
    r["window"]["strict_lines"] = 257
    r["exhibits"][0]["strict_lines"] = 257
    json.dump(r, open(p, "w"))


def site_change(pkt):
    p = os.path.join(pkt, "records.json")
    r = json.load(open(p))
    r["exhibits"][0]["bin_table_init_sites"][0] = "0x63cdaa9"
    r["bin_table_init_sites"][0]["site"] = "0x63cdaa9"
    json.dump(r, open(p, "w"))


def inject_overlap(pkt):
    # Partial overlap of #281's prior window 0x63c8d60..0x63c94fc (not an
    # exact copy, so the verifier's exact-window self-exclusion cannot hide it).
    p = os.path.join(pkt, "records.json")
    r = json.load(open(p))
    r["exhibits"].append({"name": "injected", "range": "0x63c8d60..0x63c8d70"})
    json.dump(r, open(p, "w"))


tamper("hex flip", flip_hex)
tamper("strict-count change", strict_change)
tamper("call-site change", site_change)
tamper("injected partial overlap", inject_overlap)

# independent recounts from the exhibit objdump
obj = open(os.path.join(WT, "research", "work-items", SLUG,
                        "bintableinit_caller_walk_20rsp_2sites.objdump.txt")).read()
strict = [l for l in obj.splitlines()
          if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
check("independent strict recount", len(strict) == 258, len(strict))
check("independent bti census",
      sum(1 for l in strict if re.search(r"\tcall\s+63d9880", l)) == 2)
check("independent miss census",
      sum(1 for l in strict if re.search(r"\tcall\s+63d9700", l)) == 2)
check("independent ret census",
      sum(1 for l in strict if re.search(r"\tret\s*$", l)) == 1)

# regeneration comparison: strip everything through the 'file format' line
def strip_head(text):
    lines = text.splitlines()
    for i, l in enumerate(lines):
        if "file format" in l:
            return lines[i + 1:]
    return lines


fresh = subprocess.run(["objdump", "-d", "--start-address=0x63cd910",
                        "--stop-address=0x63cddce", BIN],
                       capture_output=True, text=True).stdout
check("objdump regeneration", strip_head(fresh) == strip_head(obj))

print("TESTS FAIL count: %d" % len(fails))
sys.exit(1 if fails else 0)
