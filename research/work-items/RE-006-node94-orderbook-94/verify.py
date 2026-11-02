#!/usr/bin/env python3
"""Fail-closed replay for the bounded partial-fill caller evidence."""

import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET = ROOT / "artifacts/node/94/hl-node"
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
WINDOW_FILE_OFFSET = 0x4311289
WINDOW_LENGTH = 118
WINDOW_SHA256 = "cc7957f79f8ced525c50ca8077cec35abbbc2afb38ad38e54faed2cbc25283c7"


def fail(message):
    print(f"RE-006 node94-orderbook verify: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


# This packet's manifest pins the evidence files only; README.md is
# listed and this script is committed unlisted.
PACKET_FILES = frozenset({
    "README.md", "partial-fill-caller.tsv",
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

    target = TARGET.read_bytes()
    digest = hashlib.sha256(target).hexdigest()
    if digest != TARGET_SHA256:
        fail(f"target: {digest} != {TARGET_SHA256}")
    window = target[WINDOW_FILE_OFFSET : WINDOW_FILE_OFFSET + WINDOW_LENGTH]
    window_digest = hashlib.sha256(window).hexdigest()
    if window_digest != WINDOW_SHA256:
        fail(f"caller window: {window_digest} != {WINDOW_SHA256}")

    rows = (HERE / "partial-fill-caller.tsv").read_text().splitlines()
    windows = [row for row in rows if row.startswith("window\t")]
    if len(windows) != 1:
        fail("expected exactly one retained caller window")
    if not windows[0].startswith("window\t" + window.hex() + "\t"):
        fail("retained window bytes differ from the authenticated target")
    print("RE-006 node94-orderbook verify: OK", WINDOW_SHA256)


if __name__ == "__main__":
    main()
