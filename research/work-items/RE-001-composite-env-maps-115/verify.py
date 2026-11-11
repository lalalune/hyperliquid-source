#!/usr/bin/env python3
"""Self-check for this packet. Run from the repo root:

    python3 research/work-items/RE-001-composite-env-maps-115/verify.py

Checks: artifact digest (full 64-char SHA-256), MANIFEST.sha256, excerpts
byte-identical to fresh objdump, FDE ranges, raw-binary spot bytes
(key literals, record packs, call/lea rel32s), .rela.dyn resolutions for
the callback GOT pairs and vtable typeinfos, the lea-reference census,
semantic-only records.json, and the model tests.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def sections(data):
    out = subprocess.check_output(
        ["readelf", "-SW", str(BIN)], text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    secs = {}
    for line in out.splitlines():
        m = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
            line)
        if m:
            secs[m.group(1)] = (int(m.group(3), 16),
                                int(m.group(4), 16), int(m.group(5), 16))
    return secs


def va_bytes(data, secs, va, n):
    for _name, (addr, off, size) in secs.items():
        if addr <= va < addr + size:
            return data[off + (va - addr): off + (va - addr) + n]
    raise KeyError(f"{va:#x} not in any section")


def main():
    data = BIN.read_bytes()
    secs = sections(data)

    # 1. Artifact digest.
    check("artifact sha256", hashlib.sha256(data).hexdigest() == DIGEST)

    # 2. Manifest.
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    for line in manifest:
        h, path = line.split(None, 1)
        p = HERE / path.strip()
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != h:
            ok = False
            print(f"  manifest mismatch: {path}")
    listed = {l.split(None, 1)[1].strip() for l in manifest}
    actual = {p.name for p in HERE.iterdir()
              if p.is_file() and p.name not in ("MANIFEST.sha256", "__pycache__")}
    if listed != actual:
        ok = False
        print(f"  manifest set != dir set: extra={listed - actual} "
              f"missing={actual - listed}")
    check("MANIFEST.sha256", ok, f"{len(manifest)} files")

    # 3. Excerpts byte-identical to fresh objdump.
    funcs = {
        "fn-5fe0760-static-initializer.objdump.txt": (0x5FE0760, 0x5FE0FBC),
        "fn-5d405b0-map-insert-helper.objdump.txt": (0x5D405B0, 0x5D40F32),
    }
    ok = True
    for name, (s, e) in funcs.items():
        fresh = subprocess.check_output(
            ["objdump", "-d", f"--start-address={s:#x}",
             f"--stop-address={e:#x}", "artifacts/node/115/hl-node"],
            cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        if (HERE / name).read_text() != fresh:
            ok = False
            print(f"  excerpt differs: {name}")
    check("excerpts byte-identical", ok, f"{len(funcs)} excerpts")

    # 4. FDE ranges.
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records
    _, frames = eh_frame_records(data)
    fdes = {(f["start"], f["end"]) for f in frames}
    ok = True
    for line in (HERE / "frames.txt").read_text().splitlines()[1:]:
        _fn, s, e = line.split("\t")
        if (int(s, 16), int(e, 16)) not in fdes:
            ok = False
            print(f"  FDE missing: {s}..{e}")
    check("FDE ranges", ok)

    # 5. Raw-binary spot bytes.
    spots = [
        (0x44A390, b"target\x00", "target literal"),
        (0x44B349, b"file_system\x00", "file_system literal"),
        (0x4496D9, b"clock\x00", "clock literal"),
        (0x458F68, struct.pack("<Q", 0x100000016), "pack 0x100000016"),
        (0x4593C0, struct.pack("<Q", 0x10000001A), "pack 0x10000001a"),
    ]
    ok = True
    for va, want, label in spots:
        got = va_bytes(data, secs, va, len(want))
        if got != want:
            ok = False
            print(f"  spot mismatch {label}: {got!r} != {want!r}")
    # E8 rel32 at the three host RegisterOptions call sites -> 0x6099ce0.
    for site in (0x5FD73CB, 0x5FD73F1, 0x5FD7417):
        off = TEXT_OFF + (site - TEXT_VA)
        assert data[off] == 0xE8, f"{site:#x} is not E8"
        rel = struct.unpack_from("<i", data, off + 1)[0]
        if site + 5 + rel != 0x6099CE0:
            ok = False
            print(f"  call target mismatch at {site:#x}")
    # lea rel32 for the three maps at the host sites.
    for site, target in ((0x5FD73B9, 0x6504C60), (0x5FD73E7, 0x6504C20),
                         (0x5FD740D, 0x6504BE0)):
        off = TEXT_OFF + (site - TEXT_VA)
        rel = struct.unpack_from("<i", data, off + 3)[0]
        if site + 7 + rel != target:
            ok = False
            print(f"  lea target mismatch at {site:#x}")
    check("raw-binary spot bytes", ok, f"{len(spots)} literals/packs + "
          "3 E8 + 3 lea")

    # 6. .rela.dyn resolutions.
    a, o, s = secs[".rela.dyn"]
    relocs = {}
    for i in range(o, o + s, 24):
        off, info, add = struct.unpack_from("<QQq", data, i)
        relocs[off] = (info & 0xFFFFFFFF, info >> 32, add)
    got_pairs = {0x64ED8C8: 0x5FD5460, 0x64ED8D0: 0x5FCC660,
                 0x64ED958: 0x5FD4C30, 0x64ED960: 0x5FD7470}
    ok = all(relocs.get(va, (None, None, None))[2] == tgt
             for va, tgt in got_pairs.items())
    check("GOT callback pairs resolve", ok)
    typeinfos = {0x64CDFC8: b"N7rocksdb19CompositeEnvWrapperE",
                 0x64CD8D8: b"N7rocksdb3EnvE"}
    ok = True
    for va, want in typeinfos.items():
        r = relocs.get(va)
        if not r or r[2] is None:
            ok = False
            continue
        name = va_bytes(data, secs, r[2], len(want))
        if name != want:
            ok = False
            print(f"  typeinfo mismatch at {va:#x}: {name!r}")
    check("vtable typeinfo names", ok)

    # 7. Lea-reference census (recomputed).
    sys.path.insert(0, str(HERE))
    import census as census_mod
    refs = census_mod.scan_lea_refs(
        data, {0x6504C60, 0x6504C20, 0x6504BE0})
    ok = all(sorted(refs[a]) == sorted(census_mod.EXPECTED_LEA[a])
             for a in census_mod.EXPECTED_LEA)
    check("lea-reference census", ok,
          f"{sum(len(v) for v in refs.values())} refs")

    # 8. records.json is semantic-only.
    rec = json.loads((HERE / "records.json").read_text())
    blob = json.dumps(rec)
    bad = [k for k in ("\"mnemonic\"", "\"instructions\"", "\"opcodes\"")
           if k in blob]
    check("records.json semantic-only", not bad, f"bad keys: {bad}")
    check("records.json full digest",
          rec["artifact_sha256"] == DIGEST and len(DIGEST) == 64)

    # 9. Model tests.
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         "tests/test_composite_env_maps_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    check("model tests", r.returncode == 0,
          (r.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip().splitlines() or [""])[-1])

    failed = [n for n, ok_, _ in CHECKS if not ok_]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("FAILED:", failed)
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
