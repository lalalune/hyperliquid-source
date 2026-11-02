#!/usr/bin/env python3
"""Fail-closed replay for the committed RE-006 evidence packet."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import order_book_lifecycle_94 as lifecycle  # noqa: E402


def fail(message):
    print(f"RE-006 verify: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


# This packet's manifest pins the evidence files only; this script
# is committed unlisted.
PACKET_FILES = frozenset({
    "README.md", "evidence.json", "objdump-excerpts.txt",
})


def check_manifest():
    listed = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        expected, sep, name = line.partition("  ")
        if not sep or len(expected) != 64 or not name:
            fail(f"malformed MANIFEST.sha256 line: {line!r}")
        if name in listed:
            fail(f"MANIFEST.sha256 lists {name} twice")
        listed[name] = expected
    # The set comparisons below cannot see two entry kinds: a symlink
    # (is_file and read_bytes follow it, so a listed evidence file can
    # point outside the packet) and a subdirectory (never counted as a
    # file). The node-inventory packet verifiers reject both; mirror
    # them, tolerating only a __pycache__ of plain bytecode files.
    for entry in sorted(HERE.iterdir()):
        if entry.is_symlink():
            fail(f"packet entry is a symlink: {entry.name}")
        if entry.is_dir():
            if entry.name != "__pycache__":
                fail(f"unexpected directory in packet: {entry.name}")
            for child in sorted(entry.iterdir()):
                if child.is_symlink() or not child.is_file() \
                        or child.suffix != ".pyc":
                    fail(f"unexpected __pycache__ entry in packet: "
                         f"{child.name}")
    # Comparing the manifest only against the directory is not enough:
    # an evidence file deleted together with its manifest row leaves
    # the two sets equal. So the listed set must also equal the pinned
    # evidence set, and the directory must not hold unlisted evidence
    # files.
    if set(listed) != PACKET_FILES:
        fail(f"manifest file set differs from the pinned packet files: "
             f"missing rows {sorted(PACKET_FILES - set(listed))}, "
             f"unexpected rows {sorted(set(listed) - PACKET_FILES)}")
    present = {p.name for p in HERE.iterdir() if p.is_file()} \
        - {"MANIFEST.sha256", "verify.py"}
    if set(listed) != present:
        fail(f"manifest file set differs from packet contents: "
             f"unlisted {sorted(present - set(listed))}, "
             f"missing {sorted(set(listed) - present)}")
    for name, expected in listed.items():
        actual = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{name}: {actual} != {expected}")


def main():
    check_manifest()
    try:
        recomputed = lifecycle.render(lifecycle.scan(lifecycle.TARGET.read_bytes()))
    except (lifecycle.EvidenceError, ValueError) as exc:
        fail(str(exc))
    if recomputed != (HERE / "evidence.json").read_text():
        fail("recomputed evidence.json differs from committed bytes")
    print("RE-006 verify: OK", hashlib.sha256(recomputed.encode()).hexdigest())


if __name__ == "__main__":
    main()
