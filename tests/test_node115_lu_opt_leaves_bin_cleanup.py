#!/usr/bin/env python3
"""Unit + tamper tests for the #263 packet verifier.

Standalone: python3 tests/test_node115_lu_opt_leaves_bin_cleanup.py
Tamper cases assert the verifier FAILS (nonzero exit) on corrupted
input; they are the first line of defence (packet #257 lesson) and are
run before any green run is trusted.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research/work-items/RE-001-node115-lu-opt-leaves-bin-cleanup")
BINARY = os.path.join(REPO, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(REPO, "tools/node115_lu_opt_leaves_bin_cleanup.py")
STRICT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

passed = 0
failed = 0


def test(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print("ok -", name)
    else:
        failed += 1
        print("FAIL -", name)


def run_verifier(packet_dir):
    return subprocess.run(
        [sys.executable, VERIFIER, packet_dir, BINARY],
        capture_output=True, text=True).returncode


def regen(name, start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % end, BINARY],
        capture_output=True, text=True).stdout.splitlines()
    if len(out) >= 2 and out[0] == "" and "file format" in out[1]:
        out = out[2:]
    return out


def main():
    rec = json.load(open(os.path.join(PACKET, "records.json")))

    # 1. Regeneration comparison (header lines stripped, #262 method).
    for ex in rec["exhibits"]:
        stored = open(os.path.join(PACKET, ex["objdump"])).read().splitlines()
        if len(stored) >= 2 and stored[0] == "" and "file format" in stored[1]:
            stored = stored[2:]
        test("regen %s" % ex["name"],
             stored == regen(ex["name"], ex["start"], ex["end"]))

    # 2. Independent strict recount (test recounts, not verifier's count).
    for ex in rec["exhibits"]:
        lines = regen(ex["name"], ex["start"], ex["end"])
        n = sum(1 for line in lines if STRICT.match(line))
        test("strict %s == %d" % (ex["name"], ex["strict_instructions"]),
             n == ex["strict_instructions"])

    # 3. Totals.
    test("total bytes == 1759",
         rec["total_claimed_bytes"] == 1759)
    test("total strict == 459",
         rec["total_strict_instructions"] == 459)
    test("10 exhibits", len(rec["exhibits"]) == 10)
    test("survey sites == 108",
         sum(len(v) for v in
             rec["survey"]["bin_table_init"]["callers"].values()) == 108)
    test("leaves remaining == 161", rec["leaves_remaining_after"] == 161)

    # 4. Tamper controls (each must make the verifier FAIL). The temp
    # layout mirrors the repo (tools/ + research/work-items/<slug>/)
    # so MANIFEST's ../../../tools and ../../../tests paths resolve,
    # and a fake prior packet claiming 0x63ec7a0..0x63ec900 is planted
    # in the temp merged tree so the overlap check fires for the
    # right reason, not via a side-effect failure.
    with tempfile.TemporaryDirectory() as tmp:
        tools_dir = os.path.join(tmp, "tools")
        tests_dir = os.path.join(tmp, "tests")
        os.makedirs(tools_dir)
        os.makedirs(tests_dir)
        shutil.copy(VERIFIER, os.path.join(
            tools_dir, "node115_lu_opt_leaves_bin_cleanup.py"))
        shutil.copy(os.path.abspath(__file__), os.path.join(
            tests_dir, "test_node115_lu_opt_leaves_bin_cleanup.py"))
        wi = os.path.join(tmp, "research/work-items")
        os.makedirs(wi)
        slug = "RE-001-node115-lu-opt-leaves-bin-cleanup"
        tampered = os.path.join(wi, slug)
        shutil.copytree(PACKET, tampered)
        fake = os.path.join(wi, "RE-001-node115-fake-prior")
        os.makedirs(fake)
        json.dump({"exhibits": [{"name": "fake",
                                  "start": 0x63ec7a0, "end": 0x63ec900}]},
                  open(os.path.join(fake, "records.json"), "w"))

        def run_tmp_verifier():
            return subprocess.run(
                [sys.executable,
                 os.path.join(tools_dir, "node115_lu_opt_leaves_bin_cleanup.py"),
                 tampered, BINARY], capture_output=True, text=True)

        r = run_tmp_verifier()
        test("tamper-layout clean run passes", r.returncode == 0)
        # 4a. Hex flip: corrupt one byte of a .hex exhibit.
        p = os.path.join(tampered, "opt_hpa.hex")
        raw = bytearray(open(p, "rb").read())
        raw[10] ^= 0xFF
        open(p, "wb").write(bytes(raw))
        test("tamper hex-flip fails verifier",
             run_tmp_verifier().returncode != 0)
        shutil.rmtree(tampered)
        shutil.copytree(PACKET, tampered)
        # 4b. Strict-count change: alter records.json count only.
        rpath = os.path.join(tampered, "records.json")
        rj = json.load(open(rpath))
        rj["exhibits"][0]["strict_instructions"] += 1
        rj["total_strict_instructions"] += 1
        json.dump(rj, open(rpath, "w"), indent=1)
        test("tamper strict-count fails verifier",
             run_tmp_verifier().returncode != 0)
        shutil.rmtree(tampered)
        shutil.copytree(PACKET, tampered)
        # 4c. Injected overlap: extend bin_cleanup's claimed range into
        # the following bin_remove FDE (the fake prior's range).
        rpath = os.path.join(tampered, "records.json")
        rj = json.load(open(rpath))
        for ex in rj["exhibits"]:
            if ex["name"] == "bin_cleanup":
                ex["end"] = 0x63ec800
                ex["range"] = "0x63ec690..0x63ec800"
                ex["size"] = 0x63ec800 - 0x63ec690
        json.dump(rj, open(rpath, "w"), indent=1)
        rr = run_tmp_verifier()
        test("tamper injected-overlap fails verifier",
             rr.returncode != 0)
        test("tamper injected-overlap cites overlap",
             "overlap" in rr.stdout)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
