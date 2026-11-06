#!/usr/bin/env python3
"""Unit tests for the RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp packet.

Tamper controls run FIRST (each must fail the verifier): hex flip,
strict-count change, call-site change, injected overlap. Tampers edit parsed
JSON (never string replacement) and re-seal the MANIFEST, so the only failure
cause is the tampered claim itself. Then: clean temp copy passes, regeneration
comparisons, and independent recounts.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp"
PACKET_REL = os.path.join("research", "work-items", SLUG)
VERIFIER_REL = os.path.join("tools", "node115_lu_bintableinit_caller_walk_120rsp_4sites.py")
TEST_REL = os.path.join("tests", "test_node115_lu_bintableinit_caller_walk_120rsp_4sites.py")
HEX_NAME = "bintableinit_caller_walk_120rsp_4sites.hex"
OBJ_NAME = "bintableinit_caller_walk_120rsp_4sites.objdump.txt"
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

PASS, FAIL = [], []


def ok(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else " :: " + str(detail)))


def build_temp():
    tmp = tempfile.mkdtemp(prefix="hl283-test-", dir="/home/hatch/workspace/scratch-hl283")
    for rel in [PACKET_REL, "tools", "tests"]:
        shutil.copytree(os.path.join(ROOT, rel), os.path.join(tmp, rel))
    os.makedirs(os.path.join(tmp, "artifacts", "node", "115"), exist_ok=True)
    os.symlink(BIN, os.path.join(tmp, "artifacts", "node", "115", "hl-node"))
    return tmp


def reseal(tmp):
    pdir = os.path.join(tmp, PACKET_REL)
    lines = []
    for line in open(os.path.join(pdir, "MANIFEST.sha256")).read().splitlines():
        _h, p = line.split("  ", 1)
        fp = os.path.normpath(os.path.join(pdir, p))
        lines.append(hashlib.sha256(open(fp, "rb").read()).hexdigest() + "  " + p)
    open(os.path.join(pdir, "MANIFEST.sha256"), "w").write("\n".join(lines) + "\n")


def run_verifier(tmp):
    r = subprocess.run([sys.executable, os.path.join(tmp, VERIFIER_REL)],
                       capture_output=True, text=True, timeout=1800)
    return r.returncode


def tamper_hex(tmp):
    p = os.path.join(tmp, PACKET_REL, HEX_NAME)
    b = bytearray(open(p, "rb").read())
    b[100] ^= 0xFF
    open(p, "wb").write(bytes(b))
    reseal(tmp)


def tamper_strict(tmp):
    p = os.path.join(tmp, PACKET_REL, "records.json")
    rec = json.load(open(p))
    rec["exhibits"][0]["strict"] += 1
    json.dump(rec, open(p, "w"), indent=2, sort_keys=True)
    reseal(tmp)


def tamper_callsite(tmp):
    p = os.path.join(tmp, PACKET_REL, "records.json")
    rec = json.load(open(p))
    rec["bin_table_init_sites"][0]["site"] = "0x6350e16"
    json.dump(rec, open(p, "w"), indent=2, sort_keys=True)
    reseal(tmp)


def tamper_overlap(tmp):
    p = os.path.join(tmp, PACKET_REL, "records.json")
    rec = json.load(open(p))
    rec["exhibits"].append({"bytes": 100, "name": "injected",
                            "range": "0x6350211..0x6350275", "strict": 10})
    json.dump(rec, open(p, "w"), indent=2, sort_keys=True)
    reseal(tmp)


def main():
    # Tamper controls first.
    for name, fn in [("hex flip", tamper_hex), ("strict-count change", tamper_strict),
                     ("call-site change", tamper_callsite), ("injected overlap", tamper_overlap)]:
        tmp = build_temp()
        try:
            fn(tmp)
            rc = run_verifier(tmp)
            ok("tamper fails verifier: " + name, rc != 0, "exit %d" % rc)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # Clean temp copy passes.
    tmp = build_temp()
    try:
        rc = run_verifier(tmp)
        ok("clean temp copy passes", rc == 0, "exit %d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Regeneration comparisons.
    data = open(BIN, "rb").read()
    regen_hex = data[0x6350210 - 0x1000:0x6350210 - 0x1000 + 11598]
    exhibit_hex = open(os.path.join(ROOT, PACKET_REL, HEX_NAME), "rb").read()
    ok("hex regeneration", regen_hex == exhibit_hex)
    r = subprocess.run(["objdump", "-d", "--start-address=0x6350210",
                        "--stop-address=0x6352f5e",
                        "artifacts/node/115/hl-node"],
                       capture_output=True, text=True, cwd=ROOT, timeout=300)
    ok("objdump exit 0", r.returncode == 0)
    regen_lines = r.stdout.splitlines()
    marker = next(i for i, l in enumerate(regen_lines) if "Disassembly of section .text:" in l)
    regen_body = regen_lines[marker + 1:]
    exhibit_lines = open(os.path.join(ROOT, PACKET_REL, OBJ_NAME)).read().splitlines()
    emarker = next(i for i, l in enumerate(exhibit_lines) if "Disassembly of section .text:" in l)
    ok("objdump regeneration", regen_body == exhibit_lines[emarker + 1:])

    # Independent recounts (separate regexes from the verifier's).
    strict = [l for l in exhibit_lines if re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f ]+\t[a-z]", l)]
    calls = [l for l in exhibit_lines if "\tcall " in l]
    bti = [l for l in calls if "63d9880" in l]
    miss = [l for l in calls if "63d9700" in l]
    rets = [l for l in exhibit_lines if l.rstrip().endswith("\tret")]
    bsr = [l for l in exhibit_lines if "\tbsr " in l]
    ok("independent strict", len(strict) == 2382, len(strict))
    ok("independent calls", len(calls) == 90, len(calls))
    ok("independent bti", len(bti) == 4, len(bti))
    ok("independent miss", len(miss) == 13, len(miss))
    ok("independent ret", len(rets) == 1, len(rets))
    ok("independent bsr", len(bsr) == 14, len(bsr))

    print("PASS count: %d, FAIL count: %d" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
