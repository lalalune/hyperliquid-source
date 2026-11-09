#!/usr/bin/env python3
"""Self-checks for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ttl-option-maps-115/verify.py

Checks the artifact digest, the manifest, excerpt regeneration, FDEs,
raw-binary spot bytes, literals, lea/E8 censuses, the record packs, the
semantic-only shape of records.json, and the model tests.
Prints ALL CHECKS PASSED with the check count on success.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (virtual address, raw bytes) spot checks in .text (file offset = va - 0x1000).
SPOT_BYTES = {
    0x6207003: bytes.fromhex("c745a000040000"),   # flags 0x400 (block A)
    0x6207376: bytes.fromhex("c745a000040000"),   # flags 0x400 (block C)
    0x62074DD: bytes.fromhex("c745a000120000"),   # flags 0x1200 (block D)
    0x6207245: bytes.fromhex("4c8d35f4213000"),   # lea map 0x6509440
    0x6207556: bytes.fromhex("4c8d2d631e3000"),   # lea map 0x65093c0
    0x6206EF5: bytes.fromhex("488d35c4253000"),   # lea map 0x65094c0
    # The ttl record's own pack/flags (record at -0x1d0): movq $0x2 into
    # +0xa8 (-0x128) and movl $0x0 into +0xb0 (-0x120).
    0x62071A8: bytes.fromhex("48c785d8feffff02000000"),
    0x62071B3: bytes.fromhex("c785e0feffff00000000"),
}

CHECKS = 0


def check(cond, msg):
    global CHECKS
    CHECKS += 1
    assert cond, msg


def main() -> None:
    sys.path.insert(0, str(HERE))
    sys.path.insert(0, str(ROOT / "tools"))
    import census
    import export_excerpts
    import gen_records
    from fde_extents import eh_frame_records

    data = BIN.read_bytes()
    check(hashlib.sha256(data).hexdigest() == DIGEST, "artifact digest")

    # Regenerate everything; the generators assert the censuses.
    export_excerpts.main()
    gen_records.main()
    census.main()
    check(True, "census (lea/E8/FDE/maps/literals)")

    # Manifest: every listed file exists and matches its recorded sha256.
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    check(len(manifest) >= 8, f"manifest has {len(manifest)} files")
    for line in manifest:
        digest, name = line.split(None, 1)
        name = name.strip()
        # tools/ and tests/ entries are repo-root-relative; the rest are
        # packet-relative.
        path = (ROOT / name) if name.startswith(("tools/", "tests/")) \
            else (HERE / name)
        check(path.is_file(), f"manifest file missing: {name}")
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
              f"manifest mismatch: {name}")

    # Excerpts regenerate byte-identically.
    out = subprocess.run(
        ["objdump", "-d", "--start-address=0x6206ef0",
         "--stop-address=0x620769f", "artifacts/node/115/hl-node"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    check(out == (HERE / "fn-6206ef0.objdump.txt").read_text(),
          "excerpt regeneration")

    # FDE for the pinned initializer.
    _, frames = eh_frame_records(data)
    fdes = {(f["start"], f["end"]) for f in frames}
    for s, e in census.PINNED_FDES:
        check((s, e) in fdes, f"FDE {s:#x}..{e:#x} missing")

    # Raw-binary spot bytes.
    for va, want in SPOT_BYTES.items():
        got = data[va - 0x1000: va - 0x1000 + len(want)]
        check(got == want, f"spot bytes at {va:#x}: got {got.hex()}")

    # records.json is semantic-only: no per-instruction mnemonic list.
    text = (HERE / "records.json").read_text()
    check("mnemonic" not in text, "records.json holds mnemonics")
    check("instructions" not in text, "records.json holds instructions")
    recs = json.loads(text)
    check(recs["artifact_sha256"] == DIGEST, "records.json digest")
    check(len(recs["option_maps"]) == 5, "records.json map count")

    # Model tests.
    res = subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         "tests/test_ttl_option_maps_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    check(res.returncode == 0, f"pytest failed:\n{res.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")}\n{res.stderr}")

    print(f"ALL CHECKS PASSED ({CHECKS})")


if __name__ == "__main__":
    main()
