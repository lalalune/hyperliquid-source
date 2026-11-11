#!/usr/bin/env python3
"""Standalone tests for packet RE-001-node115-lu-opt-groups42-46-leaves.

Tamper controls run FIRST: each must make the verifier fail, and a clean
temp copy must pass. The temp-copy layout includes every MANIFEST-referenced
file (packet dir + tools + tests files), per packet #266's lesson.
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
    "RE-001-node115-lu-opt-groups42-46-leaves")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_opt_groups42_46_leaves.py")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

PASSED = 0
FAILED = 0


def check(cond, msg):
    global PASSED, FAILED
    if cond:
        PASSED += 1
    else:
        FAILED += 1
        print("FAIL:", msg)


def run_verifier(env_extra):
    env = dict(os.environ)
    env.update(env_extra)
    # The binary is immutable and sha-checked by the verifier itself, so the
    # temp copy reuses the real binary path instead of a cross-device link
    # (/tmp is a separate tmpfs from the workspace).
    env["HL271_BINARY"] = BINARY
    r = subprocess.run([sys.executable, VERIFIER], capture_output=True,
                       text=True, env=env)
    return r.returncode


def make_temp_copy(mutate=None):
    tmp = tempfile.mkdtemp(prefix="hl271-")
    pkt = os.path.join(tmp, "research", "work-items",
                       "RE-001-node115-lu-opt-groups42-46-leaves")
    os.makedirs(pkt)
    for f in os.listdir(PACKET):
        shutil.copy(os.path.join(PACKET, f), os.path.join(pkt, f))
    tools_dir = os.path.join(tmp, "tools")
    os.makedirs(tools_dir)
    shutil.copy(VERIFIER, os.path.join(
        tools_dir, "node115_lu_opt_groups42_46_leaves.py"))
    tests_dir = os.path.join(tmp, "tests")
    os.makedirs(tests_dir)
    shutil.copy(os.path.abspath(__file__), os.path.join(
        tests_dir, "test_node115_lu_opt_groups42_46_leaves.py"))
    if mutate:
        mutate(pkt, tmp)
    return tmp, pkt


def pkt_env(tmp):
    return {"HL271_PACKET_DIR": os.path.join(
        tmp, "research", "work-items",
        "RE-001-node115-lu-opt-groups42-46-leaves")}


def main():
    # --- tamper controls FIRST ---
    # 1. hex flip
    def flip_hex(pkt, tmp):
        p = os.path.join(pkt, "tcache_gc_incr_bytes.hex")
        b = bytearray(open(p, "rb").read())
        b[0] ^= 0xFF
        open(p, "wb").write(bytes(b))
    tmp, _ = make_temp_copy(flip_hex)
    try:
        check(run_verifier(pkt_env(tmp)) != 0,
              "hex flip did not fail the verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # 2. strict-count change
    def flip_strict(pkt, tmp):
        rec_p = os.path.join(pkt, "records.json")
        rec = json.load(open(rec_p))
        rec["exhibits"][0]["strict_instructions"] += 1
        json.dump(rec, open(rec_p, "w"), indent=1)
    tmp, _ = make_temp_copy(flip_strict)
    try:
        check(run_verifier(pkt_env(tmp)) != 0,
              "strict-count change did not fail the verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # 3. injected overlap via HL271_PRIOR_ROOTS
    fake = tempfile.mkdtemp(prefix="hl271-fake-")
    try:
        rec = {"exhibits": [{"range": "0x6372bd0..0x6372de7"}]}
        json.dump(rec, open(os.path.join(fake, "records.json"), "w"))
        check(run_verifier({"HL271_PRIOR_ROOTS": fake}) != 0,
              "injected overlap did not fail the verifier")
    finally:
        shutil.rmtree(fake, ignore_errors=True)
    # 4. value-byte flip (.data slot value)
    def flip_value(pkt, tmp):
        rec_p = os.path.join(pkt, "records.json")
        rec = json.load(open(rec_p))
        rec["leaves"][0]["file_value"] = "0x10001"
        json.dump(rec, open(rec_p, "w"), indent=1)
    tmp, _ = make_temp_copy(flip_value)
    try:
        check(run_verifier(pkt_env(tmp)) != 0,
              "value-byte flip did not fail the verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # 5. thp table-base flip
    def flip_thp(pkt, tmp):
        rec_p = os.path.join(pkt, "records.json")
        rec = json.load(open(rec_p))
        rec["leaves"][4]["value"] = "qword table at .data 0x64ffcc8 indexed by u32 at .bss 0x6712378"
        json.dump(rec, open(rec_p, "w"), indent=1)
    tmp, _ = make_temp_copy(flip_thp)
    try:
        check(run_verifier(pkt_env(tmp)) != 0,
              "thp table-base flip did not fail the verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # 6. clean temp copy passes
    tmp, _ = make_temp_copy()
    try:
        check(run_verifier(pkt_env(tmp)) == 0,
              "clean temp copy failed the verifier")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- regeneration + recount ---
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    data = open(BINARY, "rb").read()
    total_bytes = 0
    total_strict = 0
    for e in rec["exhibits"]:
        a, b = e["range"].split("..")
        s, en = int(a, 16), int(b, 16)
        raw = open(os.path.join(PACKET, e["hex"]), "rb").read()
        check(raw == data[s - 0x1000:en - 0x1000],
              "%s hex regeneration differs" % e["name"])
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % s,
             "--stop-address=%#x" % en, BINARY],
            capture_output=True, text=True, check=True).stdout.splitlines()
        regen = [l for l in out if l.strip() and "file format" not in l]
        stored = [l for l in open(os.path.join(PACKET, e["objdump"])).read().splitlines()
                  if l.strip() and "file format" not in l]
        check(regen == stored, "%s objdump regeneration differs" % e["name"])
        strict = sum(1 for l in stored if STRICT_RE.match(l))
        check(strict == e["strict_instructions"],
              "%s strict recount %d != %d"
              % (e["name"], strict, e["strict_instructions"]))
        total_bytes += en - s
        total_strict += e["strict_instructions"]
    check(total_bytes == 2465, "total bytes %d != 2465" % total_bytes)
    check(total_strict == 675, "total strict %d != 675" % total_strict)
    check(rec["remaining_unclassified_after"] == 121, "remaining != 121")

    print("%d passed, %d failed" % (PASSED, FAILED))
    sys.exit(0 if FAILED == 0 else 1)


if __name__ == "__main__":
    main()
