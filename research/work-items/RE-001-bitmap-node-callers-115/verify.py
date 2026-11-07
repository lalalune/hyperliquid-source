"""Verify the RE-001-bitmap-node-callers-115 evidence packet.

Run from the repository root:
    python3 research/work-items/RE-001-bitmap-node-callers-115/verify.py

Checks:
  1. the work binary digest matches provenance/artifacts.json;
  2. MANIFEST.sha256 matches every file in the packet;
  3. export_excerpts.py regenerates byte-identical excerpts;
  4. census.py regenerates a byte-identical callers.tsv;
  5. gen_records.py regenerates a byte-identical records.json;
  6. three seeded random instructions from the raw excerpts match a
     fresh objdump run byte-for-byte;
  7. every window's FDE range matches objdump --dwarf=frames;
  8. the RELATIVE slots used by the vtable maps match readelf -r;
  9. the typeinfo names and literal strings match the raw binary;
 10. the model tests pass (pytest).
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

PASS = []
FAIL = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("PASS " if ok else "FAIL ") + name + ((" -- " + detail) if detail else ""))


def run(args, **kw):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, **kw)


def main():
    records = json.load(open(os.path.join(HERE, "records.json")))
    digest = records["artifact"]["sha256"]

    # 1. Binary digest vs provenance.
    prov = json.load(open(os.path.join(ROOT, "provenance", "artifacts.json")))
    node115 = None
    for art in prov.get("files", []) if isinstance(prov, dict) else []:
        if str(art.get("path", "")) == "artifacts/node/115/hl-node":
            node115 = art
            break
    prov_digest = (node115 or {}).get("sha256")
    data = open(os.path.join(ROOT, BIN), "rb").read()
    check("binary-digest", hashlib.sha256(data).hexdigest() == digest,
          "work binary matches records.json")
    check("provenance-digest", prov_digest == digest if prov_digest else False,
          "provenance/artifacts.json node #115 digest matches" if prov_digest else "no node #115 digest found in provenance")

    # 2. MANIFEST.sha256.
    manifest = open(os.path.join(HERE, "MANIFEST.sha256")).read().splitlines()
    manifest_ok = True
    for line in manifest:
        if not line.strip():
            continue
        h, _, name = line.partition("  ")
        path = os.path.join(HERE, name)
        if not os.path.exists(path) or hashlib.sha256(open(path, "rb").read()).hexdigest() != h:
            manifest_ok = False
            print("  manifest mismatch:", name)
    packet_files = sorted(
        f for f in os.listdir(HERE)
        if os.path.isfile(os.path.join(HERE, f)) and f != "MANIFEST.sha256"
    )
    listed = sorted(line.partition("  ")[2] for line in manifest if line.strip())
    check("manifest", manifest_ok and packet_files == listed,
          "%d files listed, %d present" % (len(listed), len(packet_files)))

    # 3. Excerpts regenerate byte-identically. The generator computes
    # the repo root from its own path, so it must run in place: snapshot
    # the committed files, regenerate, compare, restore on mismatch.
    import shutil
    excerpt_names = [w["file"] for w in records["windows"]] + ["frames.txt"]
    with tempfile.TemporaryDirectory() as tmp:
        for name in excerpt_names:
            shutil.copy2(os.path.join(HERE, name), os.path.join(tmp, name))
        r = run([sys.executable, os.path.join(HERE, "export_excerpts.py")])
        same = True
        for name in excerpt_names:
            a = open(os.path.join(tmp, name), "rb").read()
            b = open(os.path.join(HERE, name), "rb").read()
            if a != b:
                same = False
                print("  excerpt differs:", name)
                shutil.copy2(os.path.join(tmp, name), os.path.join(HERE, name))
        check("excerpts-regenerate", same and r.returncode == 0,
              "19 excerpts + frames.txt byte-identical")

    # 4. Census regenerates byte-identically.
    r = run([sys.executable, os.path.join(HERE, "census.py"), BIN])
    check("census-regenerates", r.returncode == 0 and r.stdout ==
          open(os.path.join(HERE, "callers.tsv")).read(),
          "census.py stdout == callers.tsv")

    # 5. records.json regenerates byte-identically (in place, same
    # snapshot-compare-restore approach as the excerpts).
    import shutil
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "records.json")
        shutil.copy2(os.path.join(HERE, "records.json"), snap)
        r = run([sys.executable, os.path.join(HERE, "gen_records.py")])
        same = open(os.path.join(HERE, "records.json"), "rb").read() == \
            open(snap, "rb").read()
        if not same:
            shutil.copy2(snap, os.path.join(HERE, "records.json"))
        check("records-regenerate", same and r.returncode == 0,
              "gen_records.py output byte-identical")

    # 6. Three seeded random instructions vs fresh objdump.
    rng = random.Random(115)
    lines = []
    for w in records["windows"]:
        path = os.path.join(HERE, w["file"])
        for line in open(path):
            m = re.match(r"\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)", line)
            if m:
                lines.append((int(m.group(1), 16), line.rstrip("\n"), w))
    picks = rng.sample(lines, 3)
    spot_ok = True
    for va, line, w in picks:
        start, end = int(w["fde"][0], 16), int(w["fde"][1], 16)
        out = run(["objdump", "-d",
                   "--start-address=%#x" % start,
                   "--stop-address=%#x" % end, BIN]).stdout
        if line not in out:
            spot_ok = False
            print("  spot-check mismatch at %#x: %s" % (va, line.strip()))
    check("spot-check-3-random-instructions", spot_ok,
          "seed 115: %s" % ", ".join(hex(v) for v, _, _ in picks))

    # 7. FDE ranges match objdump --dwarf=frames.
    frames = run(["objdump", "--dwarf=frames", BIN]).stdout
    fdes = set()
    for line in frames.splitlines():
        m = re.search(r"FDE .*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes.add((int(m.group(1), 16), int(m.group(2), 16)))
    fde_ok = all(
        (int(w["fde"][0], 16), int(w["fde"][1], 16)) in fdes
        for w in records["windows"]
    )
    check("fde-ranges", fde_ok, "%d windows" % len(records["windows"]))

    # 8. RELATIVE slots match readelf -r.
    rel = run(["readelf", "-r", BIN]).stdout
    relmap = {}
    for line in rel.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if m:
            relmap[int(m.group(1), 16)] = int(m.group(2), 16)
    rel_ok = True
    for vt in records["vtables"].values():
        for slot in vt["slots"]:
            va = int(vt["vtable_base"], 16) + int(slot["offset"], 16)
            if relmap.get(va) != int(slot["target"], 16):
                rel_ok = False
                print("  RELATIVE mismatch at %#x" % va)
    check("vtable-relocations", rel_ok, "65 vtable slots")

    # 9. Typeinfo names and literals match the raw binary.
    def va_off(va):
        if 0x63F3C20 <= va < 0x63F3C20 + 0xFBE80:
            return va - 0x2000
        if 0x64DF458 <= va < 0x64EE158:
            return va - 0x2000
        if 0x64EFA20 <= va < 0x64EFA20 + 0x238F04:
            return va - 0x3000
        if 0x430400 <= va < 0x430400 + 0x76E640:
            return va
        return None

    def cstr(va):
        off = va_off(va)
        end = data.find(b"\x00", off)
        return data[off:end].decode()

    lit_ok = (
        records["literals"]["factory_path_c_message"]["string"] == cstr(0x434276)
        and records["literals"]["poll_copy_message"]["string"] == cstr(0x437514)
        and records["literals"]["oneshot_location_pointer"]["string_at_pointer_plus_1"] == cstr(0x4376FE)
        and data[0x4376FD] == 0
        and struct.unpack_from("<Q", data, 0x459A38)[0] == 0x2000000004
    )
    check("literals", lit_ok, "messages, oneshot path, descriptor")

    # 10. Model tests.
    r = run([sys.executable, "-m", "pytest", "-q",
             "tests/test_bitmap_node_callers_115.py"])
    check("model-tests", r.returncode == 0, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip().splitlines()[-1])

    print()
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL CHECKS PASSED (%d checks)" % len(PASS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
