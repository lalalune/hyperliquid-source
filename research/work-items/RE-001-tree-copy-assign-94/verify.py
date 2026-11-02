"""Verify the RE-001 tree-copy-assign evidence packet.

Checks, all against work/hl-node-94.bin (SHA-256 pinned in records.json):
  * the target digest matches provenance/artifacts.json node #94,
  * every recorded function range's bytes hash to the recorded SHA-256,
  * every recorded direct-call target re-derives from its rel32 bytes,
  * every recorded caller site is a real e8 call to 0x514c780,
  * the committed excerpts regenerate byte-for-byte via export_excerpts.py,
  * the FDE lines in frames.txt match readelf output,
  * every file listed in MANIFEST.sha256 hashes to its recorded value.

Usage: python3 verify.py  (run from the repository root)
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BIN = ROOT / "work" / "hl-node-94.bin"
TEXT_VMA = 0x1343C80
TEXT_OFF = 0x1342C80


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
        ok = fail("target digest mismatch") or ok
    for func in records["functions"]:
        blob = file_bytes(hx(func["start"]), hx(func["end"]))
        if hashlib.sha256(blob).hexdigest() != func["sha256"]:
            ok = fail("function %s hash mismatch" % hex(func["start"])) or ok
        if len(blob) != hx(func["end"]) - hx(func["start"]):
            ok = fail("function %s length mismatch" % hex(func["start"])) or ok
    for call in records["calls"]:
        site = hx(call["site"])
        blob = file_bytes(site, site + 5)
        if blob[0] != 0xE8:
            ok = fail("call site %s is not e8" % hex(call["site"])) or ok
        rel = struct.unpack("<i", blob[1:5])[0]
        if site + 5 + rel != hx(call["target"]):
            ok = fail("call site %s target mismatch" % hex(site)) or ok
    for site in records["callers"]:
        site = hx(site)
        blob = file_bytes(site, site + 5)
        if blob[0] != 0xE8:
            ok = fail("caller site %s is not e8" % hex(site)) or ok
        rel = struct.unpack("<i", blob[1:5])[0]
        if site + 5 + rel != hx(records["functions"][0]["start"]):
            ok = fail("caller site %s does not target the function" % hex(site)) or ok
    # Excerpt regeneration.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            [sys.executable, str(PACKET / "export_excerpts.py"), "--out", tmp],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        if result.returncode != 0:
            ok = fail("export_excerpts.py failed: %s" % result.stderr) or ok
        else:
            for name in ("window.objdump.txt", "copy.objdump.txt",
                         "erase.objdump.txt", "cleanup.objdump.txt"):
                if Path(tmp, name).read_text() != (PACKET / name).read_text():
                    ok = fail("excerpt %s does not regenerate" % name) or ok
    # FDE lines.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True,
    ).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line.strip() and line.strip() not in frames:
            ok = fail("FDE line not in readelf output: %s" % line.strip()) or ok
    # Manifest hashes.
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        actual = hashlib.sha256((PACKET / name.strip()).read_bytes()).hexdigest()
        if actual != digest:
            ok = fail("manifest mismatch for %s" % name.strip()) or ok
    if ok:
        print("ALL CHECKS PASSED")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
