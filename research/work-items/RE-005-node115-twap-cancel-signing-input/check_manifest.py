#!/usr/bin/env python3
"""Check MANIFEST.sha256 (sha256sum format, paths relative to the repository root).

Reports hash mismatches, missing files, and files that exist under the packet
directory or the crate directory but are not listed (cargo `target` directories
are ignored). Read-only. The manifest uses the sha256sum line format; this script
is the checked way to verify it because the paths are relative to the repository
root, not to the packet directory.

usage: check_manifest.py ROOT MANIFEST      exit 0 clean, 1 problems, 2 usage
"""
import hashlib
import os
import sys

CRATE = "src/node115-twap-cancel-signing-input"


def walk(root, rel):
    for base, dirs, files in os.walk(os.path.join(root, rel)):
        dirs[:] = [d for d in dirs if d != "target"]
        for name in files:
            yield os.path.relpath(os.path.join(base, name), root).replace(os.sep, "/")


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    root, manifest = sys.argv[1], sys.argv[2]
    listed, problems = {}, 0
    with open(manifest) as fh:
        for line in fh:
            digest, _, rel = line.rstrip("\n").partition("  ")
            listed[rel] = digest
    for rel, digest in sorted(listed.items()):
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            print("MISSING  " + rel)
            problems += 1
            continue
        with open(path, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() != digest:
                print("MISMATCH " + rel)
                problems += 1
    packet = os.path.relpath(os.path.dirname(os.path.abspath(manifest)), os.path.abspath(root)).replace(os.sep, "/")
    for rel in list(walk(root, packet)) + list(walk(root, CRATE)):
        if rel not in listed and rel != packet + "/MANIFEST.sha256":
            print("UNLISTED " + rel)
            problems += 1
    print("manifest: %d entries, %d problems" % (len(listed), problems))
    return 0 if problems == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
