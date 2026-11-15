#!/usr/bin/env python3
"""Static check of the node #115 facts that RE-012 node115-peers-response-set relies on.

Reads the pinned ELF, never executes or emulates it, and never writes anywhere
except the new directory given by --outdir (which must not exist and must not
be inside this packet or the crate). The pinned inputs are the three files in
spec/ and they are only read.

What it checks, per spec/:
  ranges.tsv  byte ranges (name, start VA, end VA exclusive, sha256 of the bytes)
  facts.tsv   instruction text expected at an address (decoded by GNU objdump)
  relocs.tsv  R_X86_64_RELATIVE slot -> target

The decode is GNU objdump on the extracted bytes only; there is no second,
independent decoder here. A byte or text match shows that the instructions are
the ones the notes in TIES.md describe, not that the notes interpret them
correctly.
"""
import argparse
import copy
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
HERE = os.path.dirname(os.path.realpath(__file__))
SPEC = os.path.join(HERE, "spec")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_tsv(path):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line and not line.startswith("#"):
                rows.append(line.split("\t"))
    return rows


def load_spec(spec_dir=SPEC):
    ranges = [(n, int(a, 16), int(b, 16), h) for n, a, b, h in read_tsv(os.path.join(spec_dir, "ranges.tsv"))]
    facts = [(i, int(a, 16), t, role) for i, a, t, role in read_tsv(os.path.join(spec_dir, "facts.tsv"))]
    relocs = [(int(s, 16), int(t, 16)) for s, t in read_tsv(os.path.join(spec_dir, "relocs.tsv"))]
    return ranges, facts, relocs


def segments(fh):
    fh.seek(0)
    head = fh.read(64)
    if head[:4] != b"\x7fELF" or head[4] != 2:
        raise SystemExit("not an ELF64 file")
    phoff, = struct.unpack_from("<Q", head, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", head, 0x36)
    segs = []
    for i in range(phnum):
        fh.seek(phoff + i * phentsize)
        p_type, _flags, off, vaddr, _pa, filesz, _memsz, _al = struct.unpack("<IIQQQQQQ", fh.read(56))
        if p_type == 1:
            segs.append((vaddr, off, filesz))
    return segs


def read_va(fh, segs, start, end):
    for vaddr, off, filesz in segs:
        if vaddr <= start and end <= vaddr + filesz:
            fh.seek(off + start - vaddr)
            return fh.read(end - start)
    raise SystemExit(f"range {start:#x}..{end:#x} is not inside one loadable segment")


def relocation_table(binary):
    out = subprocess.run(["readelf", "-r", "--wide", binary], capture_output=True, text=True, check=True).stdout
    table = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            table[int(parts[0], 16)] = int(parts[3], 16)
    return table


_LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")


def decode(start, data):
    """objdump text per instruction address for one byte range."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "range.bin")
        with open(path, "wb") as fh:
            fh.write(data)
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", "--no-show-raw-insn",
             f"--adjust-vma={start:#x}", path],
            capture_output=True, text=True, check=True).stdout
    text = {}
    for line in out.splitlines():
        m = _LINE.match(line)
        if m:
            ins = re.sub(r"\s*#.*$", "", m.group(2))
            ins = re.sub(r"\s+<[^>]*>", "", ins)
            text[int(m.group(1), 16)] = re.sub(r"\s+", " ", ins.strip())
    return text


def collect(binary):
    ranges, facts, relocs = load_spec()
    with open(binary, "rb") as fh:
        segs = segments(fh)
        blobs = {name: (start, read_va(fh, segs, start, end)) for name, start, end, _ in ranges}
    return {"blobs": blobs, "relocs": relocation_table(binary)}


def check(data, use_pins=True, spec=None):
    """Return a list of failure strings; empty means every pinned fact holds."""
    ranges, facts, relocs = spec or load_spec()
    failures = []
    decoded = {name: decode(start, blob) for name, (start, blob) in data["blobs"].items()}
    if use_pins:
        for name, start, end, want in ranges:
            got = hashlib.sha256(data["blobs"][name][1]).hexdigest()
            if got != want:
                failures.append(f"range {name}: sha256 {got} != pinned {want}")
    for fid, addr, want, _role in facts:
        got = None
        for name, start, end, _ in ranges:
            if start <= addr < end:
                got = decoded[name].get(addr)
                break
        if got != want:
            failures.append(f"fact {fid} @ {addr:#x}: {got!r} != {want!r}")
    for slot, target in relocs:
        got = data["relocs"].get(slot)
        if got != target:
            failures.append(f"reloc {slot:#x}: {got!r} != {target:#x}")
    return failures


def flip(data, name, offset, bit=0):
    out = copy.deepcopy(data)
    start, blob = out["blobs"][name]
    b = bytearray(blob)
    b[offset] ^= 1 << bit
    out["blobs"][name] = (start, bytes(b))
    return out


def selftest(binary):
    """Baseline first, then corruptions that must each be rejected for a stated reason."""
    data = collect(binary)
    base = check(data)
    if base:
        print("selftest: baseline FAILED:", *base[:5], sep="\n  ")
        return 1
    print("selftest: baseline passes")
    ranges, facts, relocs = load_spec()
    ok = True
    # 1. every fact, with byte pins switched off: does a one-bit flip at the
    #    instruction's first byte change the decoded text at that address?
    detected = 0
    for fid, addr, want, _ in facts:
        for name, start, end, _h in ranges:
            if start <= addr < end:
                bad = check(flip(data, name, addr - start), use_pins=False)
                if any(f.startswith(f"fact {fid} ") for f in bad):
                    detected += 1
                break
    print(f"selftest: bit flip at first byte of each fact, pins off: {detected}/{len(facts)} detected by the fact text alone")
    # 2. controls that must fail, each for the expected reason
    controls = []
    name, start, end, _ = ranges[0]
    controls.append(("range byte flip is caught by the pin", check(flip(data, name, 0)), "range "))
    wrong = copy.deepcopy(data)
    slot, target = relocs[0]
    wrong["relocs"][slot] = target + 8
    controls.append(("moved relocation target is caught", check(wrong), "reloc "))
    swapped = copy.deepcopy(data)
    swapped["relocs"].pop(slot)
    controls.append(("missing relocation is caught", check(swapped), "reloc "))
    for label, failures, prefix in controls:
        good = bool(failures) and all(f.startswith(prefix) or f.startswith("fact ") for f in failures) and any(f.startswith(prefix) for f in failures)
        print(f"selftest: {label}: {'ok' if good else 'NOT DETECTED'}")
        ok &= good
    bad_spec = (ranges, [(fid, addr, want + " x", role) for fid, addr, want, role in facts[:1]] + facts[1:], relocs)
    mis = check(data, spec=bad_spec)
    good = len(mis) == 1 and mis[0].startswith(f"fact {facts[0][0]} ")
    print(f"selftest: a wrong expected text rejects exactly that fact: {'ok' if good else 'FAILED'}")
    ok &= good
    # the bit-flip count is reported, not required to be total: some flips decode to the same text
    return 0 if ok and detected > 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", required=True, help="path to the #115 hl-node ELF")
    ap.add_argument("--outdir", help="new directory for results.txt; must not exist")
    ap.add_argument("--selftest", action="store_true", help="baseline then controls; writes nothing")
    args = ap.parse_args(argv)

    got = sha256_file(args.binary)
    if got != TARGET_SHA256:
        print(f"refusing: binary sha256 {got} is not the pinned #115 value", file=sys.stderr)
        return 2
    if args.selftest:
        return selftest(args.binary)
    if not args.outdir:
        print("--outdir is required unless --selftest", file=sys.stderr)
        return 2
    root = os.path.realpath(os.path.join(HERE, "..", "..", ".."))
    out = os.path.abspath(args.outdir)
    real_out = os.path.join(os.path.realpath(os.path.dirname(out)), os.path.basename(out))
    if os.path.lexists(out):
        print("refusing: outdir already exists", file=sys.stderr)
        return 2
    for forbidden in (HERE, os.path.join(root, "src", "node115-peers-response-set")):
        if real_out == forbidden or real_out.startswith(forbidden + os.sep):
            print("refusing: outdir is inside the packet or the crate", file=sys.stderr)
            return 2

    data = collect(args.binary)
    failures = check(data)
    ranges, facts, relocs = load_spec()
    os.mkdir(out)
    with open(os.path.join(out, "results.txt"), "w") as fh:
        fh.write(f"target_sha256 {got}\n")
        fh.write(f"ranges {len(ranges)} facts {len(facts)} relocations {len(relocs)}\n")
        fh.write(f"failures {len(failures)}\n")
        for f in failures:
            fh.write(f + "\n")
    print(f"{len(ranges)} ranges, {len(facts)} facts, {len(relocs)} relocations, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
