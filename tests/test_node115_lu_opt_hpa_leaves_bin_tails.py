"""Standalone checks for RE-001-node115-lu-opt-hpa-leaves-bin-tails.

Custom runner (not unittest TestCases): run directly with python3.
Includes regeneration comparison, independent strict recount, totals,
and tamper controls run FIRST: a hex flip, a strict-count change,
and an injected prior-range overlap must each fail the verifier,
and a clean temp copy must pass (so tamper failures are meaningful,
not harness failures).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

RESULTS = []


def test(name, cond):
    RESULTS.append((name, bool(cond)))
    print(("ok - " if cond else "FAIL - ") + name)


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    REPO, "research/work-items/RE-001-node115-lu-opt-hpa-leaves-bin-tails")
BINARY = os.path.join(REPO, "artifacts/node/115/hl-node")
VERIFIER = os.path.join(
    REPO, "tools/node115_lu_opt_hpa_leaves_bin_tails.py")
STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")


def run_verifier(packet_dir, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, VERIFIER, packet_dir, BINARY],
        capture_output=True, text=True, env=env)


def make_temp_copy():
    """Mirror the repo layout so MANIFEST ../../../ paths resolve."""
    tmp = tempfile.mkdtemp(prefix="hl264test-")
    root = os.path.join(tmp, "repo")
    pkt = os.path.join(
        root, "research/work-items/RE-001-node115-lu-opt-hpa-leaves-bin-tails")
    os.makedirs(os.path.join(root, "tools"))
    os.makedirs(os.path.join(root, "tests"))
    shutil.copytree(PACKET, pkt)
    shutil.copy(VERIFIER, os.path.join(
        root, "tools/node115_lu_opt_hpa_leaves_bin_tails.py"))
    shutil.copy(os.path.abspath(__file__), os.path.join(
        root, "tests/test_node115_lu_opt_hpa_leaves_bin_tails.py"))
    return tmp, root, pkt


def main():
    rec = json.load(open(os.path.join(PACKET, "records.json")))

    # Regeneration comparison (header line stripped).
    for e in rec["exhibits"]:
        s = int(e["range"].split("..")[0], 16)
        en = int(e["range"].split("..")[1], 16)
        regen = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % hex(s),
             "--stop-address=%s" % hex(en), BINARY],
            capture_output=True, text=True).stdout.splitlines()
        stored = open(os.path.join(PACKET, e["objdump"])).read() \
            .splitlines()
        strip = lambda ls: [l for l in ls if "file format" not in l]
        test("regen %s" % e["name"], strip(regen) == strip(stored))

    # Independent strict recount from stored objdump files.
    for e in rec["exhibits"]:
        lines = open(os.path.join(PACKET, e["objdump"])).read() \
            .splitlines()
        n = sum(1 for l in lines if STRICT_RE.match(l))
        test("strict recount %s" % e["name"],
             n == e["strict_instructions"])

    # Totals.
    test("total bytes",
         sum(e["size"] for e in rec["exhibits"]) ==
         rec["total_claimed_bytes"])
    test("total strict",
         sum(e["strict_instructions"] for e in rec["exhibits"]) ==
         rec["total_strict_instructions"])
    test("leaves remaining",
         rec["leaves_remaining_after"] == 156)

    # --- Tamper controls (must fail the verifier) ---
    # 1. Hex flip.
    tmp, root, pkt = make_temp_copy()
    try:
        hp = os.path.join(pkt, rec["exhibits"][0]["hex"])
        b = bytearray(open(hp, "rb").read())
        b[0] ^= 0xFF
        open(hp, "wb").write(bytes(b))
        r = run_verifier(pkt)
        test("tamper hex-flip fails verifier", r.returncode != 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 2. Strict-count change.
    tmp, root, pkt = make_temp_copy()
    try:
        rp = os.path.join(pkt, "records.json")
        doc = json.load(open(rp))
        doc["exhibits"][0]["strict_instructions"] += 1
        json.dump(doc, open(rp, "w"))
        r = run_verifier(pkt)
        test("tamper strict-count fails verifier", r.returncode != 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 3. Injected prior-range overlap (via HL264_PRIOR_ROOTS).
    tmp, root, pkt = make_temp_copy()
    try:
        priors = os.path.join(tmp, "priors")
        os.makedirs(priors)
        fake = {
            "packet": "RE-001-node115-fake-prior",
            "exhibits": [{"name": "fake",
                          "range": "0x636f7c0..0x636f800"}],
        }
        json.dump(fake, open(os.path.join(priors, "records.json"), "w"))
        r = run_verifier(
            pkt, {"HL264_PRIOR_ROOTS": os.path.join(priors,
                                                    "records.json")})
        test("tamper injected-overlap fails verifier",
             r.returncode != 0)
        test("tamper injected-overlap cites overlap",
             "overlap" in r.stdout.lower())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 4. Clean temp copy must pass (harness sanity).
    tmp, root, pkt = make_temp_copy()
    try:
        r = run_verifier(pkt)
        test("clean temp copy passes verifier", r.returncode == 0)
        if r.returncode != 0:
            print(r.stdout[-2000:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 5. Clean tree run passes.
    r = run_verifier(PACKET)
    test("clean tree passes verifier", r.returncode == 0)
    if r.returncode != 0:
        print(r.stdout[-2000:])

    n_pass = sum(1 for _, ok in RESULTS if ok)
    print("%d passed, %d failed" % (n_pass, len(RESULTS) - n_pass))
    if n_pass != len(RESULTS):
        sys.exit(1)


if __name__ == "__main__":
    main()
