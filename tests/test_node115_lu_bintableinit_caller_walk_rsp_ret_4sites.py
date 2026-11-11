#!/usr/bin/env python3
"""Unit tests for the node115 lu bintableinit caller rsp-ret 4sites verifier.

Tamper controls run first: each tamper must make the verifier fail, proving
the verifier actually checks what it claims. A clean temp copy must pass.
Run from the repository root.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research/work-items/RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret"
)
VERIFIER = os.path.join(ROOT, "tools/node115_lu_bintableinit_caller_walk_rsp_ret_4sites.py")
TEST_FILE = os.path.join(
    ROOT, "tests/test_node115_lu_bintableinit_caller_walk_rsp_ret_4sites.py"
)

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS %s" % name)
    else:
        FAIL += 1
        print("FAIL %s %s" % (name, detail))


def run_case(name, mutate, expect_fail=True):
    tmp = tempfile.mkdtemp(prefix="hl282case-")
    try:
        tools = os.path.join(tmp, "tools")
        os.makedirs(tools)
        shutil.copy(VERIFIER, tools)
        # MANIFEST references ../../../tools/... and ../../../tests/...,
        # so the temp layout needs those files too.
        tests = os.path.join(tmp, "tests")
        os.makedirs(tests)
        shutil.copy(TEST_FILE, tests)
        pkt = os.path.join(tmp, "research/work-items",
                            "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret")
        shutil.copytree(PACKET, pkt)
        os.makedirs(os.path.join(tmp, "artifacts/node/115"), exist_ok=True)
        os.symlink(os.path.join(ROOT, "artifacts/node/115/hl-node"),
                   os.path.join(tmp, "artifacts/node/115/hl-node"))
        mutate(pkt, tmp)
        proc = subprocess.run(
            [sys.executable, os.path.join(tools, os.path.basename(VERIFIER))],
            capture_output=True, text=True, cwd=tmp)
        if expect_fail:
            check("tamper-%s-fails" % name, proc.returncode != 0,
                  "exit %d" % proc.returncode)
        else:
            check("clean-copy-passes", proc.returncode == 0, proc.stdout[-500:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def tamper_hex(pkt, tmp):
    p = os.path.join(pkt, "bintableinit_caller_walk_rsp_ret_4sites.hex")
    b = bytearray(open(p, "rb").read())
    b[100] ^= 0xFF
    open(p, "wb").write(bytes(b))


def tamper_strict(pkt, tmp):
    import json
    p = os.path.join(pkt, "records.json")
    rec = json.load(open(p))
    rec["window"]["strict"] = 378
    json.dump(rec, open(p, "w"))


def tamper_callsite(pkt, tmp):
    import json
    p = os.path.join(pkt, "records.json")
    rec = json.load(open(p))
    rec["bin_table_init_sites"][0]["site"] = "0x636bf97"
    json.dump(rec, open(p, "w"))


def tamper_overlap(pkt, tmp):
    # Inject a fake prior record overlapping the window into the temp
    # merged tree: the verifier must flag it (self-exclusion is by exact
    # equality, so a different overlapping range must fail).
    other = os.path.join(tmp, "research/work-items/RE-001-fake-overlap-115")
    os.makedirs(other)
    import json
    json.dump({"exhibits": [{"name": "x", "range": "0x636c000..0x636c100"}]},
              open(os.path.join(other, "records.json"), "w"))


def main():
    global PASS, FAIL
    # Tamper controls FIRST.
    run_case("hex-flip", tamper_hex)
    run_case("strict-count", tamper_strict)
    run_case("call-site", tamper_callsite)
    run_case("overlap", tamper_overlap)
    run_case("clean", lambda p, t: None, expect_fail=False)

    # Regeneration comparisons: re-derive census from the exhibit.
    lines = open(os.path.join(
        PACKET, "bintableinit_caller_walk_rsp_ret_4sites.objdump.txt")).read().splitlines()
    strict = [l for l in lines if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]", l)]
    check("regen-strict", len(strict) == 379, "got %d" % len(strict))
    calls = [l for l in lines if re.search(r"\tcall\s", l)]
    check("regen-calls", len(calls) == 9, "got %d" % len(calls))
    bti = [l for l in calls if re.search(r"call\s+63d9880\s", l)]
    check("regen-bti", len(bti) == 4, "got %d" % len(bti))
    miss = [l for l in calls if re.search(r"call\s+63d9700\s", l)]
    check("regen-miss", len(miss) == 4, "got %d" % len(miss))
    rets = [l for l in lines if re.search(r"\tret\s*$", l)]
    check("regen-ret", len(rets) == 1, "got %d" % len(rets))
    check("regen-no-bsr", not any(re.search(r"\tbsr\s", l) for l in lines))
    # Self-exclusion: the verifier's disjointness must not flag its own window.
    import json
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    check("records-window-self", rec["window"]["range"] == "0x636bd90..0x636c49c")

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
