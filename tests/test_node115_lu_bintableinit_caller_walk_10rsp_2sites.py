#!/usr/bin/env python3
"""Unit tests for the #290 packet verifier. Tamper controls FIRST: each
tamper must make the TEMP COPY's verifier fail (never the original path).
Then the clean temp copy must pass, plus regeneration and independent
recounts. No string-replace tampers: all tampers edit parsed JSON."""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERIFIER = os.path.join(ROOT, "tools/node115_lu_bintableinit_caller_walk_10rsp_2sites.py")
PACKET_REL = "research/work-items/RE-001-node115-lu-bintableinit-caller-2sites-walk-10rsp"
BIN_REL = "artifacts/node/115/hl-node"

passes, fails = [], []


def check(name, ok, detail=""):
    (passes if ok else fails).append(name)
    print(("PASS " if ok else "FAIL ") + name + ((" -- " + detail) if detail else ""))


def make_temp_copy():
    tmp = tempfile.mkdtemp(prefix="hl290test_")
    tools = os.path.join(tmp, "tools")
    os.makedirs(tools)
    shutil.copy(VERIFIER, tools)
    pkt = os.path.join(tmp, PACKET_REL)
    shutil.copytree(os.path.join(ROOT, PACKET_REL), pkt)
    bindir = os.path.join(tmp, "artifacts/node/115")
    os.makedirs(bindir)
    os.symlink(os.path.join(ROOT, BIN_REL), os.path.join(bindir, "hl-node"))
    return tmp


def run_verifier(tmp):
    p = subprocess.run([sys.executable, os.path.join(tmp, "tools",
                        "node115_lu_bintableinit_caller_walk_10rsp_2sites.py")],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def tamper(name, mutate):
    tmp = make_temp_copy()
    try:
        pkt = os.path.join(tmp, PACKET_REL)
        rec_path = os.path.join(pkt, "records.json")
        rec = json.load(open(rec_path))
        mutate(tmp, pkt, rec)
        json.dump(rec, open(rec_path, "w"))
        rc, out = run_verifier(tmp)
        check("tamper %s fails verifier" % name, rc != 0,
              "rc=%d" % rc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    # Tamper controls first (parsed-JSON edits, temp-copy verifier).
    def flip_hex(tmp, pkt, rec):
        p = os.path.join(pkt, "bintableinit_caller_walk_10rsp_2sites.hex")
        b = bytearray(open(p, "rb").read())
        b[100] ^= 0xFF
        open(p, "wb").write(bytes(b))

    def strict_count(tmp, pkt, rec):
        rec["window"]["strict_lines"] = 227

    def call_site(tmp, pkt, rec):
        rec["bin_table_init_sites"][0]["site"] = "0x636baf9"

    def injected_overlap(tmp, pkt, rec):
        # Add a fake exhibit overlapping the window: must fail disjointness
        # even though it is not the exact window (self-exclusion is exact-only).
        rec["exhibits"].append({"name": "fake_overlap",
                                "range": "0x636ba00..0x636bb00"})

    tamper("hex flip", flip_hex)
    tamper("strict-count change", strict_count)
    tamper("call-site change", call_site)
    tamper("injected overlap", injected_overlap)

    # Clean temp copy passes.
    tmp = make_temp_copy()
    try:
        rc, out = run_verifier(tmp)
        check("clean temp copy passes", rc == 0, out.strip().splitlines()[-1] if out.strip() else "no output")
        # Regeneration: hex exhibit equals the binary slice.
        blob = open(os.path.join(ROOT, BIN_REL), "rb").read()
        raw = open(os.path.join(tmp, PACKET_REL, "bintableinit_caller_walk_10rsp_2sites.hex"), "rb").read()
        check("hex regeneration", raw == blob[0x636B940 - 0x1000:0x636BD90 - 0x1000])
        # Regeneration: objdump exhibit, stripped through the 'file format' line
        # (objdump output starts with a blank line, then the path line).
        p = subprocess.run(["objdump", "-d", "--start-address=0x636b940",
                            "--stop-address=0x636bd90", os.path.join(tmp, BIN_REL)],
                           capture_output=True, text=True)
        def strip_header(text):
            lines = text.splitlines()
            for i, l in enumerate(lines):
                if "file format" in l:
                    return lines[i + 1:]
            return lines
        stored = open(os.path.join(tmp, PACKET_REL,
                      "bintableinit_caller_walk_10rsp_2sites.objdump.txt")).read()
        check("objdump regeneration",
              strip_header(p.stdout) == strip_header(stored))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Independent recounts from the stored exhibit (no verifier code reused).
    blob = open(os.path.join(ROOT, BIN_REL), "rb").read()
    txt = open(os.path.join(ROOT, PACKET_REL,
               "bintableinit_caller_walk_10rsp_2sites.objdump.txt")).read().splitlines()
    STRICT = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    strict = [l for l in txt if STRICT.match(l)]
    check("independent strict 228", len(strict) == 228, str(len(strict)))

    def tgt(l):
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\tcall\s", l)
        if not m:
            return None
        byts = bytes.fromhex(m.group(2).replace(" ", ""))
        if len(byts) < 5 or byts[0] != 0xE8:
            return None
        return int(m.group(1), 16) + 5 + struct.unpack("<i", byts[1:5])[0]

    calls = [l for l in strict if re.search(r"\tcall\s", l)]
    check("independent calls 6", len(calls) == 6, str(len(calls)))
    check("independent bti sites",
          [l.split(":")[0].strip() for l in calls if tgt(l) == 0x63D9880] == ["636baf8", "636bb5d"])
    check("independent miss sites",
          [l.split(":")[0].strip() for l in calls if tgt(l) == 0x63D9700]
          == ["636bcee", "636bd81"])
    check("independent ret 1",
          [l.split(":")[0].strip() for l in strict if re.search(r"\tret\s*$", l)] == ["636ba87"])
    check("independent no outside jmp",
          [(m.group(1), m.group(3).strip().split()[0])
           for l in strict
           for m in [re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t([a-z]\S*)(.*)$", l)]
           if m and m.group(3) == "jmp" and re.match(r"^[0-9a-f]+$", m.group(4).strip().split()[0])
           and not (0x636B940 <= int(m.group(4).strip().split()[0], 16) < 0x636BD90)]
          == [])
    # Records sites match the exhibit census.
    rec = json.load(open(os.path.join(ROOT, PACKET_REL, "records.json")))
    check("records bti match",
          [s["site"] for s in rec["bin_table_init_sites"]] == ["0x636baf8", "0x636bb5d"])
    check("records miss match",
          [s["site"] for s in rec["lu_miss_sites"]]
          == ["0x636bcee", "0x636bd81"])
    # Gap bytes are int3 (padding is 0: next FDE starts exactly at window end).
    check("gap int3",
          blob[0x636B937 - 0x1000:0x636B940 - 0x1000] == b"\xcc" * 9)
    # MANIFEST entries verify.
    man = open(os.path.join(ROOT, PACKET_REL, "MANIFEST.sha256")).read().splitlines()
    ok = True
    for line in man:
        if not line.strip():
            continue
        digest, path = line.split(None, 1)
        full = os.path.normpath(os.path.join(ROOT, PACKET_REL, path.strip().lstrip("*")))
        if hashlib.sha256(open(full, "rb").read()).hexdigest() != digest:
            ok = False
    check("manifest 5 entries", ok and len([l for l in man if l.strip()]) == 5)

    print("PASS count: %d, FAIL count: %d" % (len(passes), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
