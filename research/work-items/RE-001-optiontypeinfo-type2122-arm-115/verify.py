#!/usr/bin/env python3
"""Verify the RE-001-optiontypeinfo-type2122-arm-115 packet.

Checks use artifacts/node/115/hl-node and provenance/artifacts.json.
  1. artifact digest matches provenance/artifacts.json (node #115)
  2. MANIFEST.sha256 covers every packet file and every hash matches
  3. excerpt regeneration: export_excerpts.py output is byte-identical
  4. records regeneration: gen_records.py output is byte-identical
  5. census.py passes
  6. model tests pass
  7. three seeded gate spots are byte-for-byte vs fresh objdump + raw binary
  8. every FDE in frames.txt matches readelf --debug-dump=frames-interp
  9. the model table matches records.json entries

Usage: python3 verify.py  (run from the repository root)
Prints ALL CHECKS PASSED on success; exits non-zero otherwise.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
PACKET = os.path.relpath(HERE, REPO)
ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

failures = []
checks = [0]


def check(cond, label, detail=""):
    checks[0] += 1
    print(("PASS " if cond else "FAIL ") + label + ((" -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        failures.append(label)


def run(cmd, cwd=REPO):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def main():
    data = open(BIN, "rb").read()

    # 1. artifact digest
    prov = json.load(open(os.path.join(REPO, "provenance", "artifacts.json")))
    node115 = [f for f in prov["files"] if f["path"] == "artifacts/node/115/hl-node"][0]
    check(node115["sha256"] == ARTIFACT_SHA256, "provenance digest is the pinned node #115 digest")
    check(hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256, "binary digest matches provenance")

    # 2. MANIFEST.sha256
    manifest_path = os.path.join(HERE, "MANIFEST.sha256")
    listed = {}
    if os.path.exists(manifest_path):
        for line in open(manifest_path):
            parts = line.split()
            if len(parts) == 2:
                listed[parts[1]] = parts[0]
    packet_files = sorted(
        f for f in os.listdir(HERE)
        if os.path.isfile(os.path.join(HERE, f)) and f != "MANIFEST.sha256"
        and "__pycache__" not in f)
    check(set(listed) == set(packet_files),
          "MANIFEST covers every packet file",
          "missing=%s extra=%s" % (sorted(set(packet_files) - set(listed)),
                                   sorted(set(listed) - set(packet_files))))
    for name, digest in listed.items():
        path = os.path.join(HERE, name)
        if os.path.exists(path):
            check(hashlib.sha256(open(path, "rb").read()).hexdigest() == digest,
                  "MANIFEST hash matches %s" % name)

    # 3. excerpt regeneration
    with tempfile.TemporaryDirectory() as tmp:
        r = run([sys.executable, os.path.join(HERE, "export_excerpts.py"), tmp])
        check(r.returncode == 0, "export_excerpts.py runs", r.stderr[-500:])
        for name in os.listdir(tmp):
            committed = open(os.path.join(HERE, name), "rb").read()
            check(open(os.path.join(tmp, name), "rb").read() == committed,
                  "excerpt byte-identical: %s" % name)

    # 4. records regeneration
    with tempfile.TemporaryDirectory() as tmp:
        for name in os.listdir(HERE):
            if name.endswith((".py", ".txt", ".tsv", ".json")):
                shutil.copy(os.path.join(HERE, name), os.path.join(tmp, name))
        r = run([sys.executable, os.path.join(tmp, "gen_records.py")], cwd=tmp)
        check(r.returncode == 0, "gen_records.py runs", r.stderr[-500:])
        if r.returncode == 0:
            check(open(os.path.join(tmp, "records.json"), "rb").read() ==
                  open(os.path.join(HERE, "records.json"), "rb").read(),
                  "records.json regenerates byte-identical")

    # 5. census.py
    r = run([sys.executable, os.path.join(HERE, "census.py")])
    check(r.returncode == 0 and "ALL CHECKS PASSED" in r.stdout, "census.py passes",
          r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr[-300:])

    # 6. model tests
    r = run([sys.executable, "-m", "pytest",
             "tests/test_optiontypeinfo_type2122_arm_115.py", "-q"])
    check(r.returncode == 0, "model tests pass",
          (r.stdout.strip().splitlines() or [""])[-1])

    # 7. seeded gate spots: bytes vs raw binary and instruction vs excerpt
    def text_bytes(vaddr, n):
        return data[vaddr - 0x1000: vaddr - 0x1000 + n]

    spots = [
        # (vaddr, raw bytes, excerpt file, instruction fragment)
        (0x60BF1E0, bytes.fromhex("8b85b0000000"), "fn-60bedc0-apply.objdump.txt",
         "mov    0xb0(%rbp),%eax"),
        (0x60C1345, bytes.fromhex("488d35dfa138fa"), "fn-60c1190-map-parse.objdump.txt",
         "# 44b52b"),
        (0x60900C9, bytes.fromhex("48c785c8caffff00000000"),
         None, None),  # comparator build lives in the static initializer; raw-bytes only
    ]
    for vaddr, want, excerpt, frag in spots:
        check(text_bytes(vaddr, len(want)) == want,
              "gate spot raw bytes 0x%x" % vaddr, text_bytes(vaddr, len(want)).hex())
        if frag:
            text = open(os.path.join(HERE, excerpt)).read()
            check(frag in text, "gate spot in excerpt 0x%x" % vaddr, frag)

    # 8. FDE ranges match readelf (compare as integers: readelf zero-pads)
    r = run(["readelf", "--debug-dump=frames-interp", BIN])
    fdes = set((int(a, 16), int(b, 16))
               for a, b in re.findall(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", r.stdout))
    frames = [ln.split()[0] for ln in open(os.path.join(HERE, "frames.txt"))
              if ln.strip() and not ln.startswith("#")]
    bad = []
    for f in frames:
        a, b = f.split("..")
        if (int(a, 16), int(b, 16)) not in fdes:
            bad.append(f)
    check(not bad, "frames.txt FDE ranges match readelf", bad)

    # 9. model table matches records.json
    sys.path.insert(0, os.path.join(REPO, "tools"))
    import optiontypeinfo_type2122_arm_115 as model
    records = json.load(open(os.path.join(HERE, "records.json")))
    model_rows = sorted((e[0], e[1], e[2], e[3], e[4], e[5]) for e in model.TYPE22_ENTRIES)
    rec_rows = sorted((e["map"], e["name"], e["type"], e["verification"],
                       int(e["offset"], 16), int(e["flags"], 16)) for e in records["entries"])
    check(model_rows == rec_rows, "model TYPE22_ENTRIES == records.json entries")
    check(sorted(model.REACHABLE_ENTRIES) == sorted(records["reachable_entries"]),
          "model reachable set == records.json")
    check(sorted(model.CUSTOM_PARSE_ENTRIES) == sorted(records["custom_parse_path_entries"]),
          "model custom-parse set == records.json")

    if failures:
        print("verify: %d checks, %d failures" % (checks[0], len(failures)))
        return 1
    print("verify: ALL CHECKS PASSED (%d checks)" % checks[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
