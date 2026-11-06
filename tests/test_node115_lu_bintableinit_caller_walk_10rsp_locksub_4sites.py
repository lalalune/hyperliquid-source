#!/usr/bin/env python3
"""Unit tests for the #287 packet verifier. Tamper controls run FIRST:
each tamper must make the verifier fail; the clean temp copy must pass.
Run from the worktree root. Exit 0 only when every check passes."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PACKET = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-4sites-walk-10rsp-locksub")
VERIFIER = os.path.join(
    ROOT, "tools", "node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py")
TESTS = os.path.join(
    ROOT, "tests", "test_node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py")

fails = []
passes = []


def check(name, ok, detail=""):
    (passes if ok else fails).append(name)
    print(("PASS " if ok else "FAIL ") + name + ((" -- " + detail) if detail else ""))


def run_verifier(tmp):
    v = os.path.join(tmp, "tools",
                      "node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py")
    r = subprocess.run([sys.executable, v], cwd=tmp,
                       capture_output=True, text=True, timeout=900)
    return r.returncode, r.stdout + r.stderr


def temp_copy():
    tmp = tempfile.mkdtemp(prefix="hl287-test-")
    for rel in (os.path.join("research", "work-items",
                             "RE-001-node115-lu-bintableinit-caller-4sites-walk-10rsp-locksub"),
                os.path.join("tools", "node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py"),
                os.path.join("tests", "test_node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py")):
        src = os.path.join(ROOT, rel)
        dst = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    # binary is read-only for the verifier: symlink instead of a 106MB copy
    bin_dst = os.path.join(tmp, "artifacts", "node", "115", "hl-node")
    os.makedirs(os.path.dirname(bin_dst), exist_ok=True)
    os.symlink(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"), bin_dst)
    return tmp


def tamper_records(tmp, mutate):
    p = os.path.join(tmp, "research", "work-items",
                      "RE-001-node115-lu-bintableinit-caller-4sites-walk-10rsp-locksub",
                      "records.json")
    rec = json.load(open(p))
    mutate(rec)
    json.dump(rec, open(p, "w"))


def main():
    # TAMPER 1: hex flip (flip one byte of the exhibit)
    tmp = temp_copy()
    try:
        hp = os.path.join(tmp, "research", "work-items",
                          "RE-001-node115-lu-bintableinit-caller-4sites-walk-10rsp-locksub",
                          "bintableinit_caller_walk_10rsp_locksub_4sites.hex")
        data = bytearray(open(hp, "rb").read())
        data[100] ^= 0xFF
        open(hp, "wb").write(bytes(data))
        rc, _ = run_verifier(tmp)
        check("tamper hex flip fails", rc != 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # TAMPER 2: strict-count change via parsed JSON
    tmp = temp_copy()
    try:
        tamper_records(tmp, lambda r: r.update(strict_count=406))
        rc, _ = run_verifier(tmp)
        check("tamper strict-count fails", rc != 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # TAMPER 3: call-site change via parsed JSON (site address changed)
    tmp = temp_copy()
    try:
        def mut(r):
            r["bin_table_init_sites"][0]["site"] = "0x63ecb29"
        tamper_records(tmp, mut)
        rc, _ = run_verifier(tmp)
        check("tamper call-site fails", rc != 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # TAMPER 4: injected overlap (add an overlapping exhibit to records)
    tmp = temp_copy()
    try:
        def mut(r):
            r["exhibits"].append({"name": "evil",
                                  "range": "0x63ec900..0x63ec910"})
        tamper_records(tmp, mut)
        rc, _ = run_verifier(tmp)
        check("tamper injected overlap fails", rc != 0, "rc=%d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # CLEAN temp copy passes
    tmp = temp_copy()
    try:
        rc, out = run_verifier(tmp)
        check("clean temp copy passes", rc == 0, out.strip().splitlines()[-1] if out.strip() else "no output")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # REGENERATION: hex exhibit equals the binary slice
    blob = open(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"), "rb").read()
    raw = open(os.path.join(PACKET, "bintableinit_caller_walk_10rsp_locksub_4sites.hex"), "rb").read()
    check("hex regeneration", raw == blob[0x63ec900 - 0x1000:0x63ed06d - 0x1000])

    # INDEPENDENT recounts from the objdump exhibit
    lines = open(os.path.join(PACKET, "bintableinit_caller_walk_10rsp_locksub_4sites.objdump.txt"), errors="replace").read().splitlines()
    strict_pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    strict = [ln for ln in lines if strict_pat.match(ln)]
    check("independent strict 407", len(strict) == 407, str(len(strict)))
    bti = [ln for ln in lines if "call" in ln and "63d9880" in ln]
    check("independent bti 4", len(bti) == 4)
    check("independent bti sites",
          [ln.split(":")[0].strip() for ln in bti] == ["63ecb28", "63ecb8d", "63ecc05", "63ece23"])
    miss = [ln for ln in lines if "call" in ln and "63d9700" in ln]
    check("independent miss 4", len(miss) == 4)
    locksub = [ln for ln in lines if re.search(r"\tlock sub\s", ln)]
    check("independent locksub 1 at 63eca2f",
          len(locksub) == 1 and locksub[0].split(":")[0].strip() == "63eca2f")
    rets = [ln for ln in lines if re.search(r"\tret\s*$", ln)]
    check("independent ret 0", len(rets) == 0)

    print("PASS count: %d, FAIL count: %d" % (len(passes), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
