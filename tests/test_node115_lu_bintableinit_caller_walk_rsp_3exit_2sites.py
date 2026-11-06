#!/usr/bin/env python3
"""Unit tests for the #291 packet verifier.

Tamper controls run FIRST and must make the TEMP COPY's verifier fail
(running the original path would silently pass every tamper, bug #287).
Then regeneration comparisons and independent recounts run.
Exit 0 iff every check passes.

Temp trees are created directly under ~/workspace (not /tmp) so the
verifier's prior-scan glob (ROOT/../hl-wt-calls*/...) resolves to the
real prior worktrees; they are removed afterwards. The binary is
symlinked into the temp tree, never copied.
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
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp-3exit")
VERIFIER = os.path.join(ROOT, "tools",
                        "node115_lu_bintableinit_caller_walk_rsp_3exit_2sites.py")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp-3exit"
WS = os.path.expanduser("~/workspace")
PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(detail)) if detail and not cond else ""))


def make_temp_tree():
    tmp = tempfile.mkdtemp(prefix="hl291test-", dir=WS)
    tmp_packet = os.path.join(tmp, "research", "work-items", SLUG)
    tmp_tools = os.path.join(tmp, "tools")
    tmp_tests = os.path.join(tmp, "tests")
    os.makedirs(tmp_packet, exist_ok=True)
    os.makedirs(tmp_tools, exist_ok=True)
    os.makedirs(tmp_tests, exist_ok=True)
    for f in os.listdir(PACKET):
        shutil.copy2(os.path.join(PACKET, f), os.path.join(tmp_packet, f))
    shutil.copy2(VERIFIER, os.path.join(tmp_tools, os.path.basename(VERIFIER)))
    linkdir = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(linkdir, exist_ok=True)
    os.symlink(BIN, os.path.join(linkdir, "hl-node"))
    return tmp


def run_temp_verifier(tmp):
    proc = subprocess.run(
        [sys.executable,
         os.path.join(tmp, "tools", os.path.basename(VERIFIER))],
        capture_output=True, text=True)
    return proc


def temp_copy_with(mutate):
    tmp = make_temp_tree()
    try:
        tmp_packet = os.path.join(tmp, "research", "work-items", SLUG)
        mutate(tmp_packet)
        return run_temp_verifier(tmp).returncode
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- tamper controls (parsed-JSON edits, never string-replace: #282 lesson) ---
def tamper_hex(packet_dir):
    p = os.path.join(packet_dir, "bintableinit_caller_walk_rsp_3exit_2sites.hex")
    b = bytearray(open(p, "rb").read())
    b[10] ^= 0xFF
    open(p, "wb").write(bytes(b))


def tamper_strict(packet_dir):
    p = os.path.join(packet_dir, "records.json")
    rec = json.load(open(p))
    rec["exhibits"][0]["strict_lines"] = 202
    json.dump(rec, open(p, "w"))


def tamper_callsite(packet_dir):
    p = os.path.join(packet_dir, "records.json")
    rec = json.load(open(p))
    rec["exhibits"][0]["bin_table_init_sites"] = ["0x63c8a6e", "0x63c8c17"]
    json.dump(rec, open(p, "w"))


def tamper_overlap(packet_dir):
    p = os.path.join(packet_dir, "records.json")
    rec = json.load(open(p))
    # #281's window: present in priors, so this injected exhibit must fail
    rec["exhibits"].append({"name": "injected", "range": "0x63c8d60..0x63c94fc"})
    json.dump(rec, open(p, "w"))


check("tamper hex flip fails", temp_copy_with(tamper_hex) != 0)
check("tamper strict-count fails", temp_copy_with(tamper_strict) != 0)
check("tamper call-site fails", temp_copy_with(tamper_callsite) != 0)
check("tamper injected overlap fails", temp_copy_with(tamper_overlap) != 0)

# --- clean temp copy passes ---
tmp = make_temp_tree()
try:
    proc = run_temp_verifier(tmp)
    check("clean temp copy passes", proc.returncode == 0,
          (proc.stdout.strip().splitlines()[-1] if proc.stdout else "") +
          proc.stderr[-300:])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# --- regeneration: hex ---
node = open(BIN, "rb").read()
regen_hex = node[0x63C89C0 - 0x1000:0x63C8D5A - 0x1000]
disk_hex = open(os.path.join(PACKET, "bintableinit_caller_walk_rsp_3exit_2sites.hex"), "rb").read()
check("hex regeneration", regen_hex == disk_hex)

# --- regeneration: objdump (strip everything through the 'file format' line: #288 lesson) ---
proc = subprocess.run(["objdump", "-d", "--start-address=0x63c89c0",
                       "--stop-address=0x63c8d5a", BIN],
                      capture_output=True, text=True)


def strip_header(text):
    lines = text.splitlines()
    for i, l in enumerate(lines):
        if "file format" in l:
            return lines[i + 1:]
    return lines


disk_obj = open(os.path.join(PACKET, "bintableinit_caller_walk_rsp_3exit_2sites.objdump.txt")).read()
check("objdump regeneration", strip_header(proc.stdout) == strip_header(disk_obj))

# --- independent recounts ---
lines = disk_obj.splitlines()
strict = [l for l in lines if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
check("independent strict recount", len(strict) == 201, len(strict))
calls = [l for l in strict if re.search(r"\tcall\s", l)]
check("independent call recount", len(calls) == 5, len(calls))
bti = [l for l in calls if re.search(r"\tcall\s+63d9880\s", l)]
check("independent bti recount", len(bti) == 2, len(bti))
miss = [l for l in calls if re.search(r"\tcall\s+63d9700\s", l)]
check("independent miss recount", len(miss) == 2, len(miss))
check("independent ret recount",
      sum(1 for l in strict if re.search(r"\tret\s*$", l)) == 0)
check("independent bsr recount",
      sum(1 for l in strict if re.search(r"\tbsr\s", l)) == 0)

print("PASS count: %d, FAIL count: %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)
