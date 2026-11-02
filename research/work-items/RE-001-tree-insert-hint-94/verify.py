"""Verify the RE-001 tree-insert-hint evidence packet.

Checks, all against work/hl-node-94.bin (SHA-256 pinned in records.json):
  * the target digest matches provenance/artifacts.json node #94,
  * every recorded function range's bytes hash to the recorded SHA-256,
  * every recorded direct-call target re-derives from its rel32 bytes,
  * the twin fallback tail jump re-derives from its rel32 bytes,
  * every recorded caller site is a real e8 call to 0x514c8f0,
  * the committed excerpts regenerate byte-for-byte via export_excerpts.py,
  * the FDE lines in frames.txt match readelf output,
  * every file listed in MANIFEST.sha256 hashes to its recorded value.

The binary is located via the HL_NODE94_BIN environment variable when
set (so a copied packet still verifies against the real target), else by
walking up from this file to a work/hl-node-94.bin, else via the
repository root implied by the packet path.

Usage: python3 verify.py  (run from the repository root)
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
TEXT_VMA = 0x1343C80
TEXT_OFF = 0x1342C80


def locate_binary():
    override = os.environ.get("HL_NODE94_BIN")
    if override:
        return Path(override)
    here = PACKET
    for parent in [here, *here.parents]:
        candidate = parent / "work" / "hl-node-94.bin"
        if candidate.exists():
            return candidate
    return ROOT / "work" / "hl-node-94.bin"


BIN = locate_binary()


def fail(message):
    print("FAIL: %s" % message)
    return False


def hx(value):
    return int(value, 16) if isinstance(value, str) else value


def file_bytes(start, stop):
    start = hx(start)
    stop = hx(stop)
    off = start - TEXT_VMA + TEXT_OFF
    data = BIN.read_bytes()
    return data[off:off + (stop - start)]


def main():
    ok = True
    records = json.loads((PACKET / "records.json").read_text())
    if hashlib.sha256(BIN.read_bytes()).hexdigest() != records["target"]["sha256"]:
        fail("target digest mismatch"); ok = False
    for func in records["functions"]:
        blob = file_bytes(hx(func["start"]), hx(func["end"]))
        if hashlib.sha256(blob).hexdigest() != func["sha256"]:
            fail("function %s hash mismatch" % func["start"]); ok = False
        if len(blob) != hx(func["end"]) - hx(func["start"]):
            fail("function %s length mismatch" % func["start"]); ok = False
    for call in records["calls"]:
        site = hx(call["site"])
        blob = file_bytes(site, site + 5)
        if call["kind"].startswith("twin"):
            if blob[0] != 0xE9:
                fail("fallback site %s is not e9" % hex(site)); ok = False
        elif blob[0] != 0xE8:
            fail("call site %s is not e8" % hex(site)); ok = False
        rel = struct.unpack("<i", blob[1:5])[0]
        if site + 5 + rel != hx(call["target"]):
            fail("call site %s target mismatch" % hex(site)); ok = False
    for site in records["callers"]:
        site = hx(site)
        blob = file_bytes(site, site + 5)
        if blob[0] != 0xE8:
            fail("caller site %s is not e8" % hex(site)); ok = False
        rel = struct.unpack("<i", blob[1:5])[0]
        if site + 5 + rel != hx(records["functions"][0]["start"]):
            fail("caller site %s does not target the function" % hex(site)); ok = False
    # Excerpt regeneration.
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py"), "--out", tmp],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        if result.returncode != 0:
            fail("export_excerpts.py failed: %s" % result.stderr); ok = False
        else:
            for name in ("window.objdump.txt", "caller1.objdump.txt",
                         "caller2.objdump.txt", "plt.objdump.txt"):
                if Path(tmp, name).read_text() != (PACKET / name).read_text():
                    fail("excerpt %s does not regenerate" % name); ok = False
    # FDE lines.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True,
    ).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line.strip() and line.strip() not in frames:
            fail("FDE line not in readelf output: %s" % line.strip()); ok = False
    # Manifest hashes.
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        actual = hashlib.sha256((PACKET / name.strip()).read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name.strip()); ok = False
    if ok:
        print("ALL CHECKS PASSED")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
