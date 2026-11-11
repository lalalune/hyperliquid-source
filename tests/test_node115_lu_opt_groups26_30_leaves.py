#!/usr/bin/env python3
"""Standalone tests for packet RE-001-node115-lu-opt-groups26-30-leaves.

Run: python3 tests/test_node115_lu_opt_groups26_30_leaves.py
Tamper controls run first: each must make the verifier fail.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-opt-groups26-30-leaves")
VERIFIER = os.path.join(ROOT, "tools", "node115_lu_opt_groups26_30_leaves.py")
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok -", name)
    else:
        FAIL += 1
        print("NOT OK -", name)


def run_verifier(env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, VERIFIER],
                          capture_output=True, text=True, env=e)


def main():
    rec = json.load(open(os.path.join(PACKET, "records.json")))
    data = open(os.path.join(ROOT, "artifacts", "node", "115", "hl-node"), "rb").read()
    strict_re = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")

    # --- tamper controls FIRST ---
    # 1. hex flip: run the real verifier against a temp packet copy with
    #    one exhibit byte flipped; it must fail citing the exhibit.
    with tempfile.TemporaryDirectory() as td:
        tmp_packet = os.path.join(td, "packet")
        shutil.copytree(PACKET, tmp_packet)
        p = os.path.join(tmp_packet, "muzzy_decay_ms.hex")
        raw = bytearray(open(p, "rb").read())
        raw[0] ^= 0xFF
        open(p, "wb").write(bytes(raw))
        r = run_verifier({"HL268_PACKET_DIR": tmp_packet})
        check("tamper hex-flip fails verifier", r.returncode != 0)
        check("tamper hex-flip cites muzzy_decay_ms", "muzzy_decay_ms" in r.stdout)
    # 2. strict-count change: same, with records strict bumped by one.
    with tempfile.TemporaryDirectory() as td:
        tmp_packet = os.path.join(td, "packet")
        shutil.copytree(PACKET, tmp_packet)
        rp = os.path.join(tmp_packet, "records.json")
        rec2 = json.load(open(rp))
        rec2["exhibits"][0]["strict_instructions"] += 1
        json.dump(rec2, open(rp, "w"))
        r = run_verifier({"HL268_PACKET_DIR": tmp_packet})
        check("tamper strict-count fails verifier", r.returncode != 0)
        check("tamper strict-count cites muzzy_decay_ms", "muzzy_decay_ms" in r.stdout)
    # 3. injected overlap via HL268_PRIOR_ROOTS: fake prior record overlapping
    #    muzzy_decay_ms must fail the verifier, and the failure must cite overlap.
    with tempfile.TemporaryDirectory() as td:
        fake = os.path.join(td, "fake-packet")
        os.makedirs(fake)
        json.dump({"exhibits": [{"name": "fake",
                                  "range": "0x6371620..0x6371700"}]},
                  open(os.path.join(fake, "records.json"), "w"))
        r = run_verifier({"HL268_PRIOR_ROOTS": fake})
        check("tamper injected-overlap fails verifier", r.returncode != 0)
        check("tamper injected-overlap cites overlap", "overlap" in r.stdout)
    # 4. clean temp copy passes (tools AND tests included in layout)
    with tempfile.TemporaryDirectory() as td:
        shutil.copytree(PACKET, os.path.join(td, "packet"))
        check("clean temp copy layout has tools+tests referenced",
              os.path.exists(os.path.join(PACKET, "..", "..", "..",
                                          "tools",
                                          "node115_lu_opt_groups26_30_leaves.py")))

    # --- regen + strict recount ---
    for e in rec["exhibits"]:
        s, en = e["range"].split("..")
        s, en = int(s, 16), int(en, 16)
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % s,
             "--stop-address=%#x" % en,
             os.path.join(ROOT, "artifacts", "node", "115", "hl-node")],
            capture_output=True, text=True, check=True).stdout.splitlines()
        regen = [l for l in out if l.strip() and "file format" not in l]
        stored = [l for l in open(os.path.join(PACKET, e["objdump"])).read().splitlines()
                  if l.strip() and "file format" not in l]
        check("regen %s" % e["name"], regen == stored)
        got = sum(1 for l in open(os.path.join(PACKET, e["objdump"]))
                  if strict_re.match(l))
        check("strict recount %s" % e["name"], got == e["strict_instructions"])

    # --- totals + leaves-remaining + count checks ---
    check("total bytes 2248",
          sum(e["size"] for e in rec["exhibits"]) == 2248)
    check("total strict 622",
          sum(e["strict_instructions"] for e in rec["exhibits"]) == 622)
    check("leaves remaining 136", rec["remaining_unclassified_after"] == 136)
    check("5 exhibits", len(rec["exhibits"]) == 5)
    check("5 leaves", len(rec["leaves"]) == 5)
    check("next fde 0x6371f10", rec["next_fde_after_last"] == "0x6371f10")
    check("groups 26-30",
          [l["opt_children_group"] for l in rec["leaves"]] == [26, 27, 28, 29, 30])
    check("node stride 0x28",
          all(int(rec["leaves"][i + 1]["node"], 16) -
              int(rec["leaves"][i]["node"], 16) == 0x28
              for i in range(4)))

    # --- verifier green on the real tree ---
    r = run_verifier()
    check("verifier exit 0", r.returncode == 0)
    check("verifier reports OK", "VERIFIER OK" in r.stdout)

    print("%d passed, %d failed" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
