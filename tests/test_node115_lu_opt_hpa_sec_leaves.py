"""Standalone tests for RE-001-node115-lu-opt-hpa-sec-leaves.

Custom runner (no unittest TestCases, mirroring packet #264): run with
  python3 tests/test_node115_lu_opt_hpa_sec_leaves.py
Tamper cases run FIRST: each must fail the verifier before any clean
run is trusted (packet #257 lesson).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items",
                      "RE-001-node115-lu-opt-hpa-sec-leaves")
VERIFIER = os.path.join(REPO, "tools",
                        "node115_lu_opt_hpa_sec_leaves.py")
BINARY = os.path.join(REPO, "artifacts", "node", "115", "hl-node")

PASSED = [0]
FAILED = []


def test(name, cond):
    if cond:
        PASSED[0] += 1
        print("ok -", name)
    else:
        FAILED.append(name)
        print("FAIL -", name)


def run_verifier(packet_dir, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, VERIFIER, packet_dir, BINARY],
        capture_output=True, text=True, env=env)


STRICT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")


def strip_header(lines):
    return [l for l in lines if "file format" not in l]


def main():
    records = json.load(open(os.path.join(PACKET, "records.json")))

    # --- Tamper cases FIRST ---
    with tempfile.TemporaryDirectory() as tmp:
        # 1. Hex flip must fail the verifier.
        tam = os.path.join(tmp, "hexflip")
        shutil.copytree(PACKET, tam)
        e0 = records["exhibits"][0]
        p = os.path.join(tam, e0["hex"])
        raw = bytearray(open(p, "rb").read())
        raw[0] ^= 0xFF
        open(p, "wb").write(bytes(raw))
        r = run_verifier(tam)
        test("tamper hex-flip fails verifier", r.returncode != 0)
        # 2. Strict-count change must fail the verifier.
        tam = os.path.join(tmp, "strict")
        shutil.copytree(PACKET, tam)
        rec = json.load(open(os.path.join(tam, "records.json")))
        rec["exhibits"][0]["strict_instructions"] += 1
        json.dump(rec, open(os.path.join(tam, "records.json"), "w"),
                  indent=1)
        r = run_verifier(tam)
        test("tamper strict-count fails verifier", r.returncode != 0)
        # 3. Injected overlap must fail the verifier and cite overlap.
        prior = os.path.join(tmp, "prior", "research", "work-items",
                             "FAKE", )
        os.makedirs(prior)
        fake = {"exhibits": [{"name": "fake",
                              "range": records["exhibits"][0]["range"]}]}
        json.dump(fake, open(os.path.join(prior, "records.json"), "w"))
        r = run_verifier(PACKET, {"HL265_PRIOR_ROOTS": os.path.join(
            tmp, "prior")})
        test("tamper injected-overlap fails verifier",
             r.returncode != 0)
        test("tamper injected-overlap cites overlap",
             "overlap" in r.stdout.lower())
        # 4. Clean temp copy must pass (guards against verifier
        #    false-positives from absolute paths).
        tam = os.path.join(tmp, "clean")
        shutil.copytree(PACKET, tam)
        r = run_verifier(tam)
        test("clean temp copy passes verifier", r.returncode == 0)

    # --- Clean checks ---
    r = run_verifier(PACKET)
    test("verifier exit 0 on packet dir", r.returncode == 0)
    for e in records["exhibits"]:
        lines = open(os.path.join(PACKET, e["objdump"])).read()
        lines = lines.splitlines()
        test("regen %s" % e["name"],
             strip_header(subprocess.run(
                 ["objdump", "-d",
                  "--start-address=%#x" % e["start"],
                  "--stop-address=%#x" % e["end"], BINARY],
                 capture_output=True, text=True).stdout.splitlines())
             == strip_header(lines))
        test("strict recount %s" % e["name"],
             sum(1 for l in lines if STRICT.match(l)) ==
             e["strict_instructions"])
    test("total bytes 2675",
         sum(e["size"] for e in records["exhibits"]) == 2675)
    test("total strict 735",
         sum(e["strict_instructions"] for e in records["exhibits"])
         == 735)
    test("leaves remaining 151", records["leaves_remaining_after"] == 151)
    test("five leaves classified", len(records["leaves"]) == 5)
    test("five exhibits", len(records["exhibits"]) == 5)

    print("%d passed, %d failed" % (PASSED[0], len(FAILED)))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
