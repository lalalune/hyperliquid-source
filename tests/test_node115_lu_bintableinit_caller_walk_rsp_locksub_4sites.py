#!/usr/bin/env python3
"""Unit tests for packet #285 verifier. Custom runner (not unittest TestCase):
run directly: python3 tests/test_node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py

Tamper controls run FIRST: each tamper must make the verifier fail, proving
the verifier actually checks the claim. Tampers edit parsed JSON (never string
replace -- a no-space JSON formatting bug made two #282 tampers no-ops).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SLUG = "RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub"
VERIFIER = "node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py"
TEST = "test_node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py"
HEX = "bintableinit_caller_walk_rsp_locksub_4sites.hex"
OBJDUMP = "bintableinit_caller_walk_rsp_locksub_4sites.objdump.txt"

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


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_temp_copy(root, tmp):
    """Copy packet dir + tools/tests files into the temp layout the verifier
    expects (MANIFEST references ../../../tools and ../../../tests)."""
    pkt_src = os.path.join(root, "research", "work-items", SLUG)
    pkt_dst = os.path.join(tmp, "research", "work-items", SLUG)
    shutil.copytree(pkt_src, pkt_dst)
    for sub, name in (("tools", VERIFIER), ("tests", TEST)):
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
        shutil.copy(os.path.join(root, sub, name), os.path.join(tmp, sub, name))
    # binary link (large file; symlink keeps the temp tree light)
    os.makedirs(os.path.join(tmp, "artifacts", "node", "115"), exist_ok=True)
    src_bin = os.path.join(root, "artifacts", "node", "115", "hl-node")
    dst_bin = os.path.join(tmp, "artifacts", "node", "115", "hl-node")
    if not os.path.exists(dst_bin):
        os.symlink(src_bin, dst_bin)
    return pkt_dst


def run_verifier(tmp):
    r = subprocess.run(
        [sys.executable, os.path.join(tmp, "tools", VERIFIER), "--root", tmp],
        capture_output=True, text=True)
    return r


def load_records(pkt):
    with open(os.path.join(pkt, "records.json"), "r") as f:
        return json.load(f)


def save_records(pkt, rec):
    with open(os.path.join(pkt, "records.json"), "w") as f:
        json.dump(rec, f)


def main():
    root = repo_root()
    pkt_src = os.path.join(root, "research", "work-items", SLUG)

    # --- tamper controls FIRST ---
    tmp = tempfile.mkdtemp(prefix="hl285-test-")
    try:
        pkt = build_temp_copy(root, tmp)

        # 1. hex flip: flip one byte in the .hex exhibit
        with open(os.path.join(pkt, HEX), "rb") as f:
            blob = bytearray(f.read())
        blob[100] ^= 0xFF
        with open(os.path.join(pkt, HEX), "wb") as f:
            f.write(bytes(blob))
        r = run_verifier(tmp)
        check("tamper-hex-flip-fails", r.returncode != 0, "verifier passed on flipped exhibit")

        # restore clean copy
        shutil.rmtree(tmp)
        tmp = tempfile.mkdtemp(prefix="hl285-test-")
        pkt = build_temp_copy(root, tmp)

        # 2. strict-count change via parsed JSON
        rec = load_records(pkt)
        rec["window"]["strict"] = 378
        save_records(pkt, rec)
        r = run_verifier(tmp)
        check("tamper-strict-count-fails", r.returncode != 0, "verifier passed on wrong strict count")

        shutil.rmtree(tmp)
        tmp = tempfile.mkdtemp(prefix="hl285-test-")
        pkt = build_temp_copy(root, tmp)

        # 3. call-site change via parsed JSON
        rec = load_records(pkt)
        rec["bin_table_init_sites"][0]["site"] = "0x63d31d7"
        save_records(pkt, rec)
        r = run_verifier(tmp)
        check("tamper-call-site-fails", r.returncode != 0, "verifier passed on wrong call site")

        shutil.rmtree(tmp)
        tmp = tempfile.mkdtemp(prefix="hl285-test-")
        pkt = build_temp_copy(root, tmp)

        # 4. injected overlap: a fake prior packet claiming an overlapping window
        fake_dir = os.path.join(tmp, "research", "work-items", "RE-001-node115-fake-overlap")
        os.makedirs(fake_dir)
        fake = {"window": {"start": "0x63d3100", "end": "0x63d3200"},
                "exhibits": [{"range": "0x63d3100..0x63d3200"}]}
        with open(os.path.join(fake_dir, "records.json"), "w") as f:
            json.dump(fake, f)
        r = run_verifier(tmp)
        check("tamper-injected-overlap-fails", r.returncode != 0, "verifier passed on overlapping prior")

        shutil.rmtree(tmp)
        tmp = tempfile.mkdtemp(prefix="hl285-test-")
        pkt = build_temp_copy(root, tmp)

        # --- clean temp copy passes ---
        r = run_verifier(tmp)
        check("clean-temp-copy-passes", r.returncode == 0, r.stdout[-500:] + r.stderr[-500:])

        # --- regeneration: .hex from binary slice ---
        with open(os.path.join(root, "artifacts", "node", "115", "hl-node"), "rb") as f:
            f.seek(0x63d3080 - 0x1000)
            regen = f.read(1820)
        with open(os.path.join(pkt_src, HEX), "rb") as f:
            stored = f.read()
        check("regenerate-hex", regen == stored)

        # --- regeneration: objdump strict recount (header lines stripped) ---
        out = subprocess.run(
            ["objdump", "-d", "--start-address=0x63d3080", "--stop-address=0x63d379c",
             os.path.join(root, "artifacts", "node", "115", "hl-node")],
            capture_output=True, text=True)
        strict_pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
        regen_strict = [l for l in out.stdout.splitlines() if strict_pat.match(l)]
        with open(os.path.join(pkt_src, OBJDUMP), "r") as f:
            stored_lines = f.read().splitlines()
        stored_strict = [l for l in stored_lines if strict_pat.match(l)]
        check("regenerate-objdump-strict", regen_strict == stored_strict,
              "regen %d stored %d" % (len(regen_strict), len(stored_strict)))

        # --- independent recounts from the stored objdump ---
        check("independent-strict", len(stored_strict) == 379, "got %d" % len(stored_strict))
        bti = [l for l in stored_lines if re.search(r"\tcall\s+63d9880", l)]
        miss = [l for l in stored_lines if re.search(r"\tcall\s+63d9700", l)]
        check("independent-bti", len(bti) == 4)
        check("independent-miss", len(miss) == 4)
        check("independent-ret", len([l for l in stored_lines if re.search(r"\tret\s*$", l)]) == 0)
        check("independent-bsr", len([l for l in stored_lines if re.search(r"\tbsr\s", l)]) == 0)
        check("independent-calls", len([l for l in stored_lines if re.search(r"\tcall\s", l)]) == 9)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("PASS count: %d, FAIL count: %d" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
