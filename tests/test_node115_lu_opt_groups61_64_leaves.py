#!/usr/bin/env python3
"""Unit tests for packet RE-001-node115-lu-opt-groups61-64-leaves.

Custom runner (not unittest TestCase): run this file directly.
Tamper controls run FIRST and must each make the verifier fail;
a clean temp copy must pass. The binary is reused by path, never copied.
Temp layout includes the tools AND tests files (packet #266 lesson).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SLUG = "RE-001-node115-lu-opt-groups61-64-leaves"
VERIFIER = "node115_lu_opt_groups61_64_leaves.py"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
PACKET = os.path.join(ROOT, "research/work-items", SLUG)
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

passed = 0
failed = []


def run_verifier(packet_dir, prior_roots=None):
    env = dict(os.environ)
    env["HL274_BINARY"] = BINARY
    env["HL274_PACKET_DIR"] = packet_dir
    if prior_roots is not None:
        env["HL274_PRIOR_ROOTS"] = prior_roots
    elif "HL274_PRIOR_ROOTS" in env:
        del env["HL274_PRIOR_ROOTS"]
    tmp_root = os.path.dirname(os.path.dirname(os.path.dirname(packet_dir)))
    tools = os.path.join(tmp_root, "tools", VERIFIER)
    proc = subprocess.run([sys.executable, tools], capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout


def make_temp_copy():
    tmp = tempfile.mkdtemp(prefix="hl274test")
    tools_dir = os.path.join(tmp, "tools")
    tests_dir = os.path.join(tmp, "tests")
    pkt_dir = os.path.join(tmp, "research/work-items", SLUG)
    os.makedirs(tools_dir)
    os.makedirs(tests_dir)
    os.makedirs(pkt_dir)
    shutil.copy(os.path.join(ROOT, "tools", VERIFIER), os.path.join(tools_dir, VERIFIER))
    shutil.copy(os.path.abspath(__file__), os.path.join(tests_dir, os.path.basename(__file__)))
    for f in os.listdir(PACKET):
        shutil.copy(os.path.join(PACKET, f), os.path.join(pkt_dir, f))
    return tmp, pkt_dir


def check(name, cond, extra=""):
    global passed
    if cond:
        passed += 1
        print("PASS: " + name)
    else:
        failed.append(name)
        print("FAIL: " + name + (" | " + extra if extra else ""))


def test_tamper_hex_flip():
    tmp, pkt = make_temp_copy()
    try:
        p = os.path.join(pkt, "prof_sys_thread_name.hex")
        b = bytearray(open(p, "rb").read())
        b[0] ^= 0xFF
        open(p, "wb").write(bytes(b))
        rc, out = run_verifier(pkt, prior_roots=tmp)
        check("tamper hex flip fails verifier", rc != 0, out.splitlines()[-1] if out else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_strict_change():
    tmp, pkt = make_temp_copy()
    try:
        rp = os.path.join(pkt, "records.json")
        rec = json.load(open(rp))
        rec["exhibits"][0]["strict"] += 1
        json.dump(rec, open(rp, "w"), indent=2)
        rc, out = run_verifier(pkt, prior_roots=tmp)
        check("tamper strict-count change fails verifier", rc != 0, out.splitlines()[-1] if out else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_overlap():
    tmp, pkt = make_temp_copy()
    try:
        fake_root = os.path.join(tmp, "priors")
        fake_dir = os.path.join(fake_root, "RE-001-fake-prior")
        os.makedirs(fake_dir)
        json.dump({"exhibits": [{"name": "fake", "range": ["0x6374540", "0x63745c6"]}]},
                  open(os.path.join(fake_dir, "records.json"), "w"))
        rc, out = run_verifier(pkt, prior_roots=fake_root)
        check("tamper injected overlap fails verifier", rc != 0, out.splitlines()[-1] if out else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_value_slot():
    tmp, pkt = make_temp_copy()
    try:
        p = os.path.join(pkt, "prof_sys_thread_name.objdump.txt")
        txt = open(p).read()
        assert "# 67125f0" in txt
        open(p, "w").write(txt.replace("# 67125f0", "# 67125f1", 1))
        rc, out = run_verifier(pkt, prior_roots=tmp)
        check("tamper value-slot lea fails verifier", rc != 0, out.splitlines()[-1] if out else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_temp_copy_passes():
    tmp, pkt = make_temp_copy()
    try:
        rc, out = run_verifier(pkt)
        check("clean temp copy passes verifier", rc == 0, out.splitlines()[-1] if out else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_regeneration():
    data = open(BINARY, "rb").read()
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    ok = True
    for e in rec["exhibits"]:
        s, en = int(e["range"][0], 16), int(e["range"][1], 16)
        raw = open(os.path.join(PACKET, e["name"] + ".hex"), "rb").read()
        if raw != data[s - 0x1000:en - 0x1000]:
            ok = False
    check("regeneration: .hex re-extraction matches", ok)


def test_independent_strict_recount():
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    ok = True
    for e in rec["exhibits"]:
        lines = open(os.path.join(PACKET, e["name"] + ".objdump.txt")).read().splitlines()
        # independent path: split on tab, mnemonic must start lowercase
        count = 0
        for l in lines:
            parts = l.split("\t")
            if len(parts) >= 3 and re.match(r"^[0-9a-f]+:$", parts[0].strip()) \
                    and re.match(r"^[0-9a-f ]+$", parts[1].strip()) \
                    and parts[2][:1].islower():
                count += 1
        if count != e["strict"]:
            ok = False
    check("independent strict recount matches records", ok)


def main():
    # Tamper controls FIRST (packet #257 lesson).
    test_tamper_hex_flip()
    test_tamper_strict_change()
    test_tamper_overlap()
    test_tamper_value_slot()
    test_clean_temp_copy_passes()
    test_regeneration()
    test_independent_strict_recount()
    print("%d passed, %d failed" % (passed, len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
