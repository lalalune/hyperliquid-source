#!/usr/bin/env python3
"""The file manifest of this contribution: the packet and the crate, in one list.

Usage:
  python3 -I manifest.py <repository root> --check MANIFEST.sha256     (read only)
  python3 -I manifest.py <repository root> --outdir NEW_DIR            (writes NEW_DIR/MANIFEST.sha256)

Covered, as paths relative to the repository root: every file under
research/work-items/RE-008-node115-nested-certificate-decision/ except MANIFEST.sha256 itself, and every file of
src/node115-nested-certificate-decision/ (Cargo.toml, Cargo.lock, rust-toolchain.toml, README.md, src/, tests/;
a `target` directory is ignored). The three reused crates, node115-stake-predicate,
node115-certificate-long-sort and node115-varint-buffer-writer, are files of the base commit and are not listed. --check exits 1 if a listed
file is missing or differs, or if a file of the covered set is not listed. --outdir must not exist yet or be an
empty directory outside the covered directories.
"""
import hashlib
import os
import sys

PACKET = "research/work-items/RE-008-node115-nested-certificate-decision"
CRATE = "src/node115-nested-certificate-decision"


def covered(root):
    paths = []
    for base in (PACKET, CRATE):
        for d, dirs, files in os.walk(os.path.join(root, base)):
            dirs[:] = sorted(x for x in dirs if x != "target")
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/")
                if rel != PACKET + "/MANIFEST.sha256":
                    paths.append(rel)
    return sorted(paths)


def digest(root, rel):
    with open(os.path.join(root, rel), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    args = sys.argv[1:]
    if not args or ("--check" not in args and "--outdir" not in args):
        sys.exit(__doc__)
    root = os.path.abspath(args[0])
    files = covered(root)
    if "--check" in args:
        listed = {}
        with open(args[args.index("--check") + 1], encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    h, p = line.rstrip("\n").split("  ", 1)
                    listed[p] = h
        problems = []
        for p, h in sorted(listed.items()):
            if not os.path.isfile(os.path.join(root, p)):
                problems.append("missing  " + p)
            elif digest(root, p) != h:
                problems.append("differs  " + p)
        problems += ["unlisted " + p for p in files if p not in listed]
        print("manifest entries %d, covered files %d, problems %d" % (len(listed), len(files), len(problems)))
        for p in problems:
            print(p)
        sys.exit(1 if problems else 0)
    out = os.path.realpath(args[args.index("--outdir") + 1])
    for base in (PACKET, CRATE):
        b = os.path.realpath(os.path.join(root, base))
        if out == b or out.startswith(b + os.sep):
            sys.exit("--outdir must not be inside " + b)
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        sys.exit("--outdir must not exist yet or be an empty directory")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "MANIFEST.sha256"), "w", newline="\n") as f:
        f.write("".join("%s  %s\n" % (digest(root, p), p) for p in files))
    print("wrote %d entries" % len(files))


if __name__ == "__main__":
    main()
