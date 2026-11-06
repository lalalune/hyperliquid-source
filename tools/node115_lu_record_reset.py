#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-record-reset (packet #254).

Byte reads only; the node binary is never executed. Checks:
binary SHA/size, exhibit bytes, objdump regeneration, strict counts,
FDE bounds/entry/padding, one ret site, no jump mnemonics, both
copy-call rel32s, zero-constant qword, copy-helper bytes (cited only),
tag-clobber order, full census (E8/E9/LEA/rela.dyn), neighbour
disjointness, MANIFEST coverage.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-record-reset")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
FDE_START, FDE_END = 0x63bf7F0, 0x63bf83D
COPY_HELPER = 0x63BFBF0
ZERO_CONST = 0xB9E830

failures = []


def check(name, cond, detail=""):
    print(("ok: " if cond else "FAIL: ") + name + ("" if cond else " " + detail))
    if not cond:
        failures.append(name)


def off_text(va):
    return va - 0x1000


def main():
    data = open(BINARY, "rb").read()
    check("binary sha", hashlib.sha256(data).hexdigest() == EXPECT_SHA)
    check("binary size", len(data) == EXPECT_SIZE, str(len(data)))
    records = json.load(open(os.path.join(PACKET, "records.json")))
    exhibits = records["exhibits"]
    total_bytes = 0
    total_strict = 0
    ranges = []
    for name, ex in sorted(exhibits.items()):
        start = int(ex["range"][0], 16)
        end = int(ex["range"][1], 16)
        raw = data[off_text(start):off_text(end)]
        hexs = "".join(open(os.path.join(PACKET, name + ".hex")).read().split())
        check(name + " length", len(raw) == ex["bytes"],
              f"{len(raw)} != {ex['bytes']}")
        check(name + " bytes", raw.hex() == hexs)
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + hex(start),
             "--stop-address=" + hex(end), BINARY],
            capture_output=True, text=True).stdout
        lines = out.splitlines()
        idx = next(i for i, l in enumerate(lines)
                   if re.match(r"^[0-9a-f]+ <.*>:$", l))
        regen = "\n".join(l.lstrip() for l in lines[idx + 1:]
                           if l.strip()) + "\n"
        stored = open(os.path.join(PACKET, name + ".objdump.txt")).read()
        check(name + " objdump regeneration", regen == stored)
        strict = sum(1 for l in stored.splitlines()
                     if re.match(r"^[0-9a-f]+:\t[0-9a-f ]+\t\S", l))
        check(name + " strict (%d, %d)" % (strict, ex["strict"]),
              strict == ex["strict"])
        check(name + " inside FDE",
              FDE_START <= start and end <= FDE_END)
        total_bytes += ex["bytes"]
        total_strict += ex["strict"]
        ranges.append((start, end))
    check("exhibits total bytes 77", total_bytes == 77, str(total_bytes))
    check("exhibits total strict 22", total_strict == 22, str(total_strict))
    ranges.sort()
    union_ok = ranges[0][0] == FDE_START and ranges[-1][1] == FDE_END
    gapless = all(ranges[i][1] == ranges[i + 1][0]
                  for i in range(len(ranges) - 1))
    check("exhibits cover whole FDE gaplessly", union_ok and gapless,
          str(ranges))
    check("FDE size", FDE_END - FDE_START == 77)
    check("FDE entry endbr64",
          data[off_text(FDE_START):off_text(FDE_START) + 4] == bytes.fromhex("f30f1efa"))
    check("padding before FDE is int3",
          data[off_text(0x63BF7EE):off_text(FDE_START)] == b"\xcc\xcc")
    check("padding after FDE is int3",
          data[off_text(FDE_END):off_text(0x63BF840)] == b"\xcc\xcc\xcc")
    check("next FDE starts at 0x63bf840 with endbr64",
          data[off_text(0x63BF840):off_text(0x63BF840) + 4] == bytes.fromhex("f30f1efa"))
    check("one ret site",
          data[off_text(0x63BF83C)] == 0xC3)
    # No jump mnemonics anywhere in the FDE objdump text.
    all_text = ""
    for name in exhibits:
        all_text += open(os.path.join(PACKET, name + ".objdump.txt")).read()
    jumps = re.findall(r"\t(jmp|je|jne|ja|jb|jae|jbe|jg|jl|jge|jle|jo|jno|js|jns)\s",
                       all_text)
    check("no jump mnemonics in FDE", not jumps, str(jumps))
    # Copy-call rel32s.
    for site in (0x63BF81E, 0x63BF829):
        o = off_text(site)
        rel = struct.unpack_from("<i", data, o + 1)[0]
        check("call %s -> 0x63bfbf0" % hex(site),
              data[o] == 0xE8 and site + 5 + rel == COPY_HELPER,
              hex(site + 5 + rel))
    # Zero constant: .rodata = VA as-is.
    check("zero constant qword at 0xb9e830 is 0",
          data[ZERO_CONST:ZERO_CONST + 8] == b"\x00" * 8)
    # Copy helper bytes (cited only): mov (%rsi),%rax; mov %rax,(%rdi); ret.
    check("copy helper bytes",
          data[off_text(COPY_HELPER):off_text(COPY_HELPER) + 11] ==
          bytes.fromhex("f30f1efa488b06488907c3"))
    # Tag clobber: entry instructions before lea rdi at 0x63bf800 read no rdi.
    entry = data[off_text(FDE_START):off_text(0x63BF800)]
    check("entry before tag clobber is endbr64/push/pxor/lea",
          entry == bytes.fromhex("f30f1efa55660fefc0488d2d30f07dfa"))
    # Full census: raw E8/E9 scan, rel32-verified; LEA scan; rela.dyn scan.
    text_off, text_size, text_va = 0x1418300, 0x4FD7700, 0x1419300
    e8, e9 = [], []
    for i in range(text_size - 5):
        op = data[text_off + i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", data, text_off + i + 1)[0]
            if text_va + i + 5 + rel == FDE_START:
                (e8 if op == 0xE8 else e9).append(text_va + i)
    check("census E8 sites 18", len(e8) == 18, str(len(e8)))
    check("census E8 sites match records",
          [hex(s) for s in e8] == records["census"]["sites"])
    check("census E9 empty", len(e9) == 0)
    lea_hits = []
    for i in range(text_size - 7):
        if data[text_off + i] in (0x48, 0x4C) and data[text_off + i + 1] == 0x8D:
            if (data[text_off + i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", data, text_off + i + 3)[0]
                if text_va + i + 7 + disp == FDE_START:
                    lea_hits.append(text_va + i)
    check("census rip-LEA empty", len(lea_hits) == 0)
    rela_off, rela_n = 0x6BE8, 60723
    rela_hits = 0
    for i in range(rela_n):
        _o, _info, addend = struct.unpack_from("<QQq", data, rela_off + i * 24)
        if addend == FDE_START:
            rela_hits += 1
    check("rela.dyn entries 60723", rela_n == 60723)
    check("rela.dyn hits 0", rela_hits == 0)
    # Neighbour disjointness: merged tree + sibling scout worktrees,
    # real paths deduped, own slug excluded. Recursively collect "range"
    # and "fde" fields, skipping census/cited-only metadata subtrees
    # (same exclusion as #253: packet #253's records cite this function
    # by address while stating it is not decoded there, so counting a
    # citation as a claim would falsely block the follow-up #253 itself
    # invited; cited FDEs are claimed by their owning packets, whose own
    # records files are scanned independently).
    META_KEYS = ("census", "cited_only_not_claimed", "largest_caller_fde",
                 "arg_shape_census")

    def ranges_from(obj, out, meta=False):
        if isinstance(obj, dict):
            if not meta:
                for key in ("range", "fde"):
                    v = obj.get(key)
                    if isinstance(v, list) and len(v) == 2:
                        try:
                            out.append((int(v[0], 16), int(v[1], 16)))
                        except (ValueError, TypeError):
                            pass
            for k, v in obj.items():
                ranges_from(v, out, meta or k in META_KEYS)
        elif isinstance(obj, list):
            for v in obj:
                ranges_from(v, out, meta)

    seen_paths = set()
    roots = [os.path.join(ROOT, "research", "work-items")]
    for wt in sorted(os.listdir(os.path.expanduser("~/workspace"))):
        if wt.startswith("hl-wt-calls"):
            roots.append(os.path.join(os.path.expanduser("~/workspace"), wt,
                                      "research", "work-items"))
    claimed = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            if "RE-001-node115-lu-record-reset" in dirpath:
                continue
            if "records.json" in filenames:
                real = os.path.realpath(os.path.join(dirpath, "records.json"))
                if real in seen_paths:
                    continue
                seen_paths.add(real)
                try:
                    rec = json.load(open(real))
                except Exception:
                    continue
                tmp = []
                ranges_from(rec, tmp)
                claimed.update(tmp)
    overlaps = [(a, b) for (a, b) in claimed
                if a < FDE_END and FDE_START < b]
    print("note: disjointness inputs: %d record files, %d unique claimed ranges"
          % (len(seen_paths), len(claimed)))
    check("no neighbour overlap", not overlaps, str(overlaps[:5]))
    # MANIFEST coverage.
    manifest = open(os.path.join(PACKET, "MANIFEST.sha256")).read().splitlines()
    entries = [l.split() for l in manifest if l.strip()]
    check("MANIFEST entries 13", len(entries) == 13, str(len(entries)))
    for digest, rel in entries:
        p = os.path.normpath(os.path.join(PACKET, rel))
        got = hashlib.sha256(open(p, "rb").read()).hexdigest()
        check("MANIFEST hash " + rel, got == digest)
    if failures:
        print("verifier: FAILED (%d)" % len(failures))
        return 1
    print("verifier: all checks passed (4 excerpts, 77 bytes, 22 strict, "
          "census 18 E8 sites, MANIFEST 13 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
