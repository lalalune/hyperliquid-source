#!/usr/bin/env python3
"""Unit tests for RE-001-node115-lu-bintableinit-caller-2sites-strinsert-18rsp.

Runs the TEMP COPY's verifier (never the original path), with tamper
controls first. Temp roots are workspace-adjacent so the verifier's
ROOT/../hl-wt-calls*/ prior glob resolves; the binary is a symlink,
not a shim. Tamper reverts restore records.json BYTES (a json.dump
rewrite changes bytes and breaks the MANIFEST hash even when values
are identical).
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
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-strinsert-18rsp"
PACKET_REL = os.path.join("research", "work-items", SLUG)
VERIFIER = "node115_lu_bintableinit_caller_strinsert_18rsp_2sites.py"
TESTS = "test_node115_lu_bintableinit_caller_strinsert_18rsp_2sites.py"
NAME = "bintableinit_caller_strinsert_18rsp_2sites"

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL: %s %s" % (name, detail))


def make_temp():
    tmp = tempfile.mkdtemp(prefix="hl295test-", dir=os.path.expanduser("~/workspace"))
    packet = os.path.join(tmp, PACKET_REL)
    shutil.copytree(os.path.join(ROOT, PACKET_REL), packet)
    tools = os.path.join(tmp, "tools")
    os.makedirs(tools)
    shutil.copy(os.path.join(ROOT, "tools", VERIFIER), tools)
    tests = os.path.join(tmp, "tests")
    os.makedirs(tests)
    shutil.copy(os.path.join(ROOT, "tests", TESTS), tests)
    arts = os.path.join(tmp, "artifacts", "node", "115")
    os.makedirs(arts)
    os.symlink(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"),
                os.path.join(arts, "hl-node"))
    return tmp


def run_temp_verifier(tmp):
    r = subprocess.run([sys.executable,
                        os.path.join(tmp, "tools", VERIFIER)],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    tmp = make_temp()
    try:
        rc, out = run_temp_verifier(tmp)
        check("clean temp-copy verifier passes", rc == 0, out[-500:])
        check("clean temp verifier 96 checks",
              "PASS count: 96, FAIL count: 0" in out, out[-300:])

        packet = os.path.join(tmp, PACKET_REL)
        rec_path = os.path.join(packet, "records.json")
        orig_rec_bytes = open(rec_path, "rb").read()
        hex_path = os.path.join(packet, NAME + ".hex")

        def tamper_records(mut):
            rec = json.loads(orig_rec_bytes.decode())
            mut(rec)
            open(rec_path, "wb").write(
                json.dumps(rec, indent=1).encode())

        # 1. hex flip
        orig_hex = open(hex_path, "rb").read()
        flipped = bytearray(orig_hex)
        flipped[10] ^= 0xFF
        open(hex_path, "wb").write(bytes(flipped))
        rc, out = run_temp_verifier(tmp)
        check("hex flip fails temp verifier", rc != 0)
        open(hex_path, "wb").write(orig_hex)

        # 2. strict-count change
        tamper_records(lambda r: r["exhibits"][0].__setitem__("strict", 107))
        rc, out = run_temp_verifier(tmp)
        check("strict-count change fails temp verifier", rc != 0)
        open(rec_path, "wb").write(orig_rec_bytes)

        # 3. call-site change
        tamper_records(lambda r: r["exhibits"][0].__setitem__(
            "bin_table_init_sites", ["0x63d4535", "0x63d4570"]))
        rc, out = run_temp_verifier(tmp)
        check("call-site change fails temp verifier", rc != 0)
        open(rec_path, "wb").write(orig_rec_bytes)

        # 4. injected partial overlap of #281's window (partial range,
        # not an exact copy, so exact-window self-exclusion cannot hide it)
        def inject(r):
            r["exhibits"].append({
                "name": "injected_overlap",
                "range": "0x63c8d00..0x63c8e00",
                "bytes": 256,
            })
        tamper_records(inject)
        rc, out = run_temp_verifier(tmp)
        check("injected overlap fails temp verifier", rc != 0)
        open(rec_path, "wb").write(orig_rec_bytes)

        # after reverts, clean again
        rc, out = run_temp_verifier(tmp)
        check("temp verifier passes after reverts", rc == 0, out[-300:])

        # independent recounts from the exhibit (not from records)
        lines = open(os.path.join(ROOT, PACKET_REL,
                                  NAME + ".objdump.txt")).read().splitlines()
        strict = [l for l in lines
                  if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
        check("independent strict recount 106", len(strict) == 106,
              "got %d" % len(strict))
        calls = [l for l in lines if re.search(r"\tcall\s", l)]
        check("independent call recount 11", len(calls) == 11,
              "got %d" % len(calls))
        bti = [l for l in calls if "63d9880" in l]
        check("independent bti recount 2", len(bti) == 2, "got %d" % len(bti))
        rets = [l for l in lines if re.search(r"\tret\s*$", l)]
        check("independent ret recount 1", len(rets) == 1, "got %d" % len(rets))

        # objdump regeneration (strip through 'file format' line)
        regen = subprocess.run(
            ["objdump", "-d", "--start-address=0x63d4497",
             "--stop-address=0x63d463e",
             os.path.join(ROOT, "artifacts", "node", "115", "hl-node")],
            capture_output=True, text=True).stdout.splitlines()

        def body(ls):
            for idx, l in enumerate(ls):
                if "file format" in l:
                    return ls[idx + 1:]
            return ls
        exhibit = open(os.path.join(ROOT, PACKET_REL,
                                    NAME + ".objdump.txt")).read().splitlines()
        check("objdump regeneration matches exhibit",
              body(regen) == body(exhibit))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("TESTS PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
