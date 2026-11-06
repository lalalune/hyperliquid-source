#!/usr/bin/env python3
"""Unit tests for the #293 packet verifier.

Builds a temp copy of the packet + tools + tests under ~/workspace
(workspace-adjacent so the temp verifier's ROOT/../hl-wt-calls* prior
glob resolves), symlinks the node binary, and runs the TEMP copy's
verifier (never the original path). Tamper controls edit parsed JSON,
never string-replace. Exit 0 iff every check passes.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

WT = "/home/hatch/workspace/hl-wt-calls293-115"
SLUG = "RE-001-node115-lu-bintableinit-caller-2sites-walk-18rsp"
VERIFIER = "tools/node115_lu_bintableinit_caller_walk_18rsp_2sites.py"

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name, detail)


def build_temp():
    tmp = tempfile.mkdtemp(prefix="hl293-test-", dir="/home/hatch/workspace")
    os.makedirs(os.path.join(tmp, "research", "work-items"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "tools"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "tests"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "artifacts", "node", "115"), exist_ok=True)
    shutil.copytree(
        os.path.join(WT, "research", "work-items", SLUG),
        os.path.join(tmp, "research", "work-items", SLUG))
    for f in (VERIFIER,
              "tests/test_node115_lu_bintableinit_caller_walk_18rsp_2sites.py"):
        shutil.copy(os.path.join(WT, f), os.path.join(tmp, f))
    os.symlink(os.path.join(WT, "artifacts", "node", "115", "hl-node"),
               os.path.join(tmp, "artifacts", "node", "115", "hl-node"))
    return tmp


def run_verifier(tmp):
    r = subprocess.run([sys.executable, os.path.join(tmp, VERIFIER)],
                       capture_output=True, text=True, timeout=1200)
    return r


def objdump_lines():
    txt = open(os.path.join(
        WT, "research", "work-items", SLUG,
        "bintableinit_caller_walk_18rsp_2sites.objdump.txt")).read()
    return [l for l in txt.splitlines()
            if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]


def main():
    tmp = build_temp()
    try:
        # 1. clean temp copy passes
        r = run_verifier(tmp)
        check("clean temp verifier exit 0", r.returncode == 0,
              r.stdout[-500:] + r.stderr[-500:])
        m = re.search(r"PASS count: (\d+), FAIL count: (\d+)", r.stdout)
        check("clean temp verifier reports 0 failures",
              m is not None and m.group(2) == "0", r.stdout[-300:])

        # 2. tamper: hex flip (first byte of the window)
        rec_path = os.path.join(tmp, "research", "work-items", SLUG,
                                "records.json")
        hex_path = os.path.join(
            tmp, "research", "work-items", SLUG,
            "bintableinit_caller_walk_18rsp_2sites.hex")
        orig_hex = open(hex_path, "rb").read()
        bad = bytearray(orig_hex)
        bad[0] ^= 0xFF
        open(hex_path, "wb").write(bytes(bad))
        r = run_verifier(tmp)
        check("hex-flip tamper fails temp verifier", r.returncode != 0)
        open(hex_path, "wb").write(orig_hex)

        # 3. tamper: strict-count change via parsed JSON
        orig_rec = open(rec_path, "rb").read()
        rec = json.load(open(rec_path))
        rec["window"]["strict_lines"] = 71
        json.dump(rec, open(rec_path, "w"))
        r = run_verifier(tmp)
        check("strict-count tamper fails temp verifier", r.returncode != 0)
        open(rec_path, "wb").write(orig_rec)

        # 4. tamper: call-site change via parsed JSON
        rec = json.load(open(rec_path))
        rec["exhibits"][0]["bin_table_init_sites"][0] = "0x63d41aa"
        json.dump(rec, open(rec_path, "w"))
        r = run_verifier(tmp)
        check("call-site tamper fails temp verifier", r.returncode != 0)
        open(rec_path, "wb").write(orig_rec)

        # 5. tamper: injected partial overlap of #281's window
        # (partial, not an exact copy, so exact-window self-exclusion
        # cannot hide it)
        rec = json.load(open(rec_path))
        rec["exhibits"].append({
            "name": "injected_overlap",
            "range": "0x63c8d60..0x63c8e00"})
        json.dump(rec, open(rec_path, "w"))
        r = run_verifier(tmp)
        check("injected-overlap tamper fails temp verifier",
              r.returncode != 0)
        open(rec_path, "wb").write(orig_rec)

        # 6. clean again after tampers reverted
        r = run_verifier(tmp)
        check("reverted temp verifier exit 0", r.returncode == 0,
              r.stdout[-500:] + r.stderr[-500:])

        # 7. independent recounts from the objdump exhibit
        lines = objdump_lines()
        check("independent strict recount 70", len(lines) == 70,
              "got %d" % len(lines))
        calls = [l for l in lines if re.search(r"\tcall\s", l)]
        check("independent call recount 5", len(calls) == 5,
              "got %d" % len(calls))
        bti = [l for l in calls if "63d9880" in l]
        check("independent bti recount 2", len(bti) == 2,
              "got %d" % len(bti))

        # 8. objdump regeneration (strip through 'file format')
        regen = subprocess.run(
            ["objdump", "-d", "--start-address=0x63d4171",
             "--stop-address=0x63d4289",
             os.path.join(WT, "artifacts", "node", "115", "hl-node")],
            capture_output=True, text=True).stdout.splitlines()
        exhibit = open(os.path.join(
            WT, "research", "work-items", SLUG,
            "bintableinit_caller_walk_18rsp_2sites.objdump.txt")
        ).read().splitlines()

        def strip(lines):
            for i, l in enumerate(lines):
                if "file format" in l:
                    return lines[i + 1:]
            return lines
        check("objdump regeneration matches exhibit",
              strip(regen) == strip(exhibit))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("TESTS PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
