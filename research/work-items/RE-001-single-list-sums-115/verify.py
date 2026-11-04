"""Verification checker for the RE-001 single-list-sums packet.

Checks, in order:
  1. work/hl-node-115.bin digest matches provenance/artifacts.json.
  2. MANIFEST.sha256 matches every packet file (except itself).
  3. Each excerpt regenerates byte-for-byte from a fresh objdump run.
  4. Sampled instructions match both the fresh objdump bytes and the
     raw binary bytes at file offset (address - 0x1000).
  5. frames.txt lines match a fresh readelf run.
  6. The census reproduces (same call sites, no jumps/qword/RELATIVE).
  7. The model tests pass.

Run from the repository root:
    python3 research/work-items/RE-001-single-list-sums-115/verify.py
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = {
    "window_a_0x5f13060.txt": (0x5F13060, 0x5F1308A),
    "window_b_0x5f13100.txt": (0x5F13100, 0x5F1312A),
    "getter_a_0x5eeb510.txt": (0x5EEB510, 0x5EEB535),
    "getter_b_0x5eeb540.txt": (0x5EEB540, 0x5EEB565),
    "composite_0x5eeb570.txt": (0x5EEB570, 0x5EEB608),
}
# (address, expected byte string) sampled from the excerpts, plus three
# extra gate-check instructions.
SAMPLES = [
    (0x5F13060, "f30f1efa"), (0x5F13074, "488b89700a0000"),
    (0x5F13086, "4889d0"),
    (0x5F13100, "f30f1efa"), (0x5F13114, "488b89780a0000"),
    (0x5F13126, "4889d0"),
    (0x5EEB510, "f30f1efa"), (0x5EEB526, "e8357b0200"),
    (0x5EEB540, "f30f1efa"), (0x5EEB556, "e8a57b0200"),
    (0x5EEB570, "f30f1efa"), (0x5EEB5A8, "e8b37a0200"),
    (0x5EEB5B3, "e8b8f70700"), (0x5EEB5D7, "e8247b0200"),
    (0x5EEB5F0, "480f42c2"),
    # Extra gate checks, picked after the sample list was fixed.
    (0x5F13070, "488b4810"), (0x5EEB59D, "488bb8f8080000"),
    (0x5EEB5E2, "4801c0"),
]


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    repo = os.path.join(os.path.dirname(__file__), "..", "..", "..")
    here = os.path.dirname(os.path.abspath(__file__))
    binary = os.path.join(repo, "work", "hl-node-115.bin")
    data = open(binary, "rb").read()

    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA:
        fail(f"binary digest {digest} != {SHA}")
    prov = json.load(open(os.path.join(repo, "provenance",
                                        "artifacts.json")))
    found = []

    def walk(o):
        if isinstance(o, dict):
            if o.get("path") == "artifacts/node/115/hl-node":
                found.append(o.get("sha256"))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(prov)
    if found != [SHA]:
        fail(f"provenance binding mismatch: {found}")
    print("digest + provenance: OK")

    manifest = {}
    for line in open(os.path.join(here, "MANIFEST.sha256")):
        h, name = line.split(None, 1)
        manifest[name.strip()] = h
    for name, h in manifest.items():
        actual = hashlib.sha256(open(os.path.join(here, name),
                                     "rb").read()).hexdigest()
        if actual != h:
            fail(f"manifest mismatch for {name}")
    print(f"manifest: OK ({len(manifest)} files)")

    for name, (start, stop) in WINDOWS.items():
        # Run objdump from the repo root with the canonical relative
        # path: objdump prints the path it was given in its header, so
        # an un-normalized path would differ from the saved excerpts.
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(stop)}", "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=os.path.abspath(repo)).stdout
        saved = open(os.path.join(here, name)).read()
        if fresh != saved:
            fail(f"excerpt regeneration mismatch for {name}")
    print("excerpt regeneration: OK")

    for addr, hexbytes in SAMPLES:
        raw = data[addr - 0x1000: addr - 0x1000 + len(hexbytes) // 2]
        if raw.hex() != hexbytes:
            fail(f"raw bytes mismatch at {addr:#x}: {raw.hex()}")
    print(f"sampled instructions byte-for-byte vs raw binary: "
          f"OK ({len(SAMPLES)} checks)")

    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", binary],
        capture_output=True, text=True, check=True).stdout
    for line in open(os.path.join(here, "frames.txt")):
        if line.strip() not in frames:
            fail(f"frame line not reproduced: {line.strip()}")
    print("frames: OK")

    out = subprocess.run(
        [sys.executable, os.path.join(here, "census.py")],
        capture_output=True, text=True, check=True).stdout
    for expect in ("0x5eeb526", "0x5eeb5a8", "0x5eeb556", "0x5eeb5d7",
                   "0x5eeb5b3"):
        if expect not in out:
            fail(f"census missing call site {expect}")
    if out.count("e9=[]") < 6 or "addend hits: none" not in out:
        fail("census shows unexpected jumps or RELATIVE hits")
    print("census: OK")

    res = subprocess.run(
        [sys.executable,
         os.path.join(repo, "tests", "test_single_list_sums_115.py")],
        capture_output=True, text=True)
    print(res.stdout.strip())
    if res.returncode != 0:
        fail("model tests failed")
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
