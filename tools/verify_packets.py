#!/usr/bin/env python3
"""Verify every evidence-packet manifest hashes exactly its referenced bytes.

`make verify` authenticates the pinned binaries and imports, but the packets
under research/work-items/ are the unit CONTRIBUTING.md asks researchers to
commit. Without this check a packet file can drift or vanish while every
tooling gate stays green. Each manifest line must be sha256sum format
(`<64 lowercase hex digits>  <relative path>`); rows resolve against the
manifest directory, then its ancestors up to the repository root, matching
the spellings the packets actually use; a row that resolves anywhere must
name an existing file whose digest matches, duplicated entries and empty
manifests are rejected, and no path may leave the repository. Rows that
resolve nowhere — historical snapshots whose payload was never committed —
are grandfathered: they are counted and reported, since inventing an anchor
would falsify what the packet attests.
"""
import hashlib
import os
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKETS = 'research/work-items'
MANIFEST_NAMES = ('MANIFEST.sha256', 'manifest.sha256')
ENTRY = re.compile(r'^([0-9a-f]{64})  (\S.*)$')


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def manifests_under(root):
    packets = root / PACKETS
    if not packets.is_dir():
        raise ValueError(f'Missing packet tree: {PACKETS}')
    seen = set()
    for name in MANIFEST_NAMES:
        for path in sorted(packets.rglob(name)):
            key = str(path).lower()  # One spelling per directory.
            if key in seen:
                continue
            seen.add(key)
            yield path


def resolved(root, packet, relative):
    """First existing (ancestor, relative) join inside the repository.

    Spellings in the wild anchor at the manifest's own directory (generator
    packets), at the packet root one or more levels above (bridge/evidence),
    at review-session ancestors whose snapshots reference their live twins,
    or at the repository root (tool/test rows); the digest binds whichever
    bytes the first existing join yields. Returns None when no join exists.
    """
    for ancestor in (packet, *packet.parents):
        if not ancestor.is_relative_to(root):
            break
        candidate = ancestor / relative
        if candidate.exists():
            absolute = candidate.resolve()
            if not absolute.is_relative_to(root):
                raise ValueError(f'Manifest path outside the repository: {relative}')
            return absolute
    return None


def parse_manifest(path):
    """Return [(digest, relative)] for readable, duplicate-free entries."""
    rows, seen = [], set()
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        match = ENTRY.match(text)
        if not match:
            raise ValueError(f'Malformed manifest entry in {path}: {line}')
        want, relative = match.groups()
        if relative in seen:
            raise ValueError(f'Duplicate manifest entry: {relative}')
        seen.add(relative)
        rows.append((want, relative))
    if not rows:
        raise ValueError(f'Empty packet manifest: {path}')
    return rows


def verify(root):
    """Hash every resolvable manifest entry against the bytes it references."""
    root = root.resolve()
    checked = total = dangling = 0
    for path in manifests_under(root):
        checked += 1
        for want, relative in parse_manifest(path):
            target = resolved(root, path.parent, relative)
            if target is None:
                dangling += 1  # Historical snapshot row; payload never committed.
                continue
            if not target.is_file():
                raise ValueError(f'Manifest lists a missing file: {relative}')
            if digest(target) != want:
                raise ValueError(f'Packet file digest mismatch: {relative}')
            total += 1
    print(f'Verified {checked} evidence-packet manifests and {total} entries '
          f'({dangling} grandfathered rows reference no committed file).')


if __name__ == '__main__':
    try:
        verify(ROOT)
    except (ValueError, OSError) as error:
        print(f'verify_packets: {error}', file=sys.stderr)
        sys.exit(1)
