#!/usr/bin/env python3
"""Static verifier for packet #267 (RE-001 node-115, opt children groups 21-25).

Byte reads only; the node binary is never executed. All paths resolve from
HL267_ROOT (or, by default, the repository root derived from this file's
location: tools/ -> parent.parent). HL267_BINARY overrides the binary path
(used by the temp-copy test). HL267_PRIOR_ROOTS (colon-separated) overrides
the prior-record roots used by the disjointness check.
"""
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lu-opt-groups21-25-leaves"
BASE = "05bc2de303c05525b71e7e257426e741bc66a390"
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN_SIZE = 105896032

ROOT = os.environ.get("HL267_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(ROOT, "research", "work-items", SLUG)
BINARY = os.environ.get("HL267_BINARY") or os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

LEAVES = [
    # name, node, group, handler_start, handler_end, size_kind, size_bytes,
    # value_desc, file_value (None when runtime-unknown)
    ("oversize_threshold", 0x64DE628, 21, 0x6370F30, 0x6371147, "u64", 8,
     "qword at .data 0x64ffb70", 0x800000),
    ("mutex_max_spin", 0x64DE650, 22, 0x6370D10, 0x6370F27, "u64", 8,
     "qword at .data 0x64ffc98", 0x258),
    ("background_thread", 0x64DE678, 23, 0x6371150, 0x63711D6, "u8", 1,
     "byte at .bss 0x6711b30", None),
    ("max_background_threads", 0x64DE6A0, 24, 0x63711E0, 0x63713F7, "u64", 8,
     "qword at .data 0x64ffbc8", 0x1000),
    ("dirty_decay_ms", 0x64DE6C8, 25, 0x6371400, 0x6371617, "u64", 8,
     "qword at .data 0x64ffb78", 0x2710),
]

# (leaf, lea_target_hex, load_substring) checks for the value-load triple.
LOAD_CHECKS = {
    "oversize_threshold": [("lea", "64ffb70"), ("mov", "(%rdx),%rdi")],
    "mutex_max_spin": [("lea", "64ffc98"), ("mov", "(%rdx),%rdi")],
    "background_thread": [("lea", "6711b30"), ("movzbl", "(%rax),%esi")],
    "max_background_threads": [("lea", "64ffbc8"), ("mov", "(%rdx),%rdi")],
    "dirty_decay_ms": [("lea", "64ffb78"), ("mov", "(%rdx),%rdi")],
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
ADDR_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(\S.*)$")

passes = []
failures = []


def ok(msg):
    passes.append(msg)


def fail(msg):
    failures.append(msg)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def objdump_lines(start, end):
    r = run(["objdump", "-d", "--start-address=%s" % hex(start),
             "--stop-address=%s" % hex(end), BINARY])
    if r.returncode != 0:
        fail("objdump failed for %s..%s" % (hex(start), hex(end)))
        return []
    out = []
    for line in r.stdout.splitlines():
        m = ADDR_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(3), line))
    return out


def strict_lines(start, end):
    r = run(["objdump", "-d", "--start-address=%s" % hex(start),
             "--stop-address=%s" % hex(end), BINARY])
    if r.returncode != 0:
        return []
    return [l for l in r.stdout.splitlines() if STRICT_RE.match(l)]


def parse_sections():
    r = run(["readelf", "-S", "--wide", BINARY])
    secs = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[0].startswith("["):
            try:
                secs[parts[1]] = (int(parts[3], 16), int(parts[4], 16), int(parts[5], 16))
            except ValueError:
                pass
    return secs


def parse_eh_frame(secs):
    addr, off, size = secs[".eh_frame"]
    data = open(BINARY, "rb").read()

    def u32(p):
        return struct.unpack_from("<I", data, p)[0]

    def sdata4(p):
        return struct.unpack_from("<i", data, p)[0]

    pos = off
    fdes = {}
    while pos < off + size:
        ln = u32(pos)
        if ln == 0:
            break
        cie_ptr = u32(pos + 4)
        if cie_ptr != 0:
            field_va = addr + (pos + 8 - off)
            init = sdata4(pos + 8) + field_va
            rng = u32(pos + 12)
            fdes[init] = rng
        pos += 4 + ln
    return fdes


def parse_rela_dyn():
    r = run(["readelf", "-r", BINARY])
    rel = {}
    for line in r.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if m:
            rel[int(m.group(1), 16)] = int(m.group(3), 16)
    return rel


SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde", "fde")


def parse_range_value(v):
    """Return (start, end) ints from a range value, or None."""
    if isinstance(v, str) and ".." in v:
        a, b = v.split("..")
        return (int(a, 16), int(b, 16))
    if isinstance(v, list) and len(v) == 2:
        def num(x):
            return int(x, 16) if isinstance(x, str) else int(x)
        return (num(v[0]), num(v[1]))
    return None


def collect_ranges(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS:
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else (v.values() if isinstance(v, dict) else [])
                for e in items:
                    if not isinstance(e, dict):
                        continue
                    if "range" in e:
                        r = parse_range_value(e["range"])
                        if r:
                            out.append(r)
                    elif "start" in e and "end" in e:
                        s, en = e["start"], e["end"]
                        s = int(s, 16) if isinstance(s, str) else int(s)
                        en = int(en, 16) if isinstance(en, str) else int(en)
                        out.append((s, en))
            else:
                collect_ranges(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out)


def main():
    data = open(BINARY, "rb").read()
    if len(data) != BIN_SIZE:
        fail("binary size %d != %d" % (len(data), BIN_SIZE))
    else:
        ok("binary size")
    if hashlib.sha256(data).hexdigest() != BIN_SHA256:
        fail("binary sha256 mismatch")
    else:
        ok("binary sha256")

    rec_path = os.path.join(PACKET_DIR, "records.json")
    try:
        rec = json.load(open(rec_path))
    except Exception as e:
        print("VERIFIER FAIL: cannot read records.json: %s" % e)
        return 1
    if rec.get("base") != BASE:
        fail("records base != %s" % BASE)
    else:
        ok("records base")
    if rec.get("packet") != SLUG:
        fail("records packet != %s" % SLUG)
    else:
        ok("records packet")

    exhibits = {}
    if isinstance(rec, dict):
        for e in rec.get("exhibits", []):
            exhibits[e["name"]] = e
    if len(exhibits) != 5:
        fail("expected 5 exhibits, got %d" % len(exhibits))
    else:
        ok("5 exhibits")

    secs = parse_sections()
    if ".text" not in secs or ".eh_frame" not in secs:
        fail("missing .text/.eh_frame sections")
        print("VERIFIER FAIL (%d failures)" % len(failures))
        for f in failures:
            print("FAIL: " + f)
        return 1
    fdes = parse_eh_frame(secs)
    if 0x6370480 not in fdes or fdes[0x6370480] != 525:
        fail("eh_frame sanity: packet #266 FDE 0x6370480 != 525B")
    else:
        ok("eh_frame sanity (#266 FDE)")
    if 0x636F9E0 not in fdes or fdes[0x636F9E0] != 535:
        fail("eh_frame sanity: packet #265 FDE 0x636f9e0 != 535B")
    else:
        ok("eh_frame sanity (#265 FDE)")
    rel = parse_rela_dyn()
    if len(rel) != 59534:
        fail("RELATIVE count %d != 59534" % len(rel))
    else:
        ok("RELATIVE count 59534")

    # .text E8 census (raw scan, exact rel32 targets).
    taddr, toff, tsize = secs[".text"]
    raw = data[toff:toff + tsize]
    e8targets = {}
    for i in range(len(raw) - 5):
        if raw[i] == 0xE8:
            tgt = taddr + i + 5 + struct.unpack_from("<i", raw, i + 1)[0]
            e8targets[tgt] = e8targets.get(tgt, 0) + 1

    total_bytes = 0
    total_strict = 0
    mine = []
    for (name, node, group, s, e, kind, nbytes, vdesc, fval) in LEAVES:
        ex = exhibits.get(name)
        if ex is None:
            fail("missing exhibit %s" % name)
            continue
        # records range values are computed, never hand-written: cross-check.
        if ex.get("start") != s or ex.get("end") != e:
            fail("%s records start/end != %s..%s" % (name, hex(s), hex(e)))
        else:
            ok("%s records range" % name)
        rng = parse_range_value(ex.get("range", ""))
        if rng != (s, e):
            fail("%s records range string != %s..%s" % (name, hex(s), hex(e)))
        else:
            ok("%s records range string" % name)
        if ex.get("size") != e - s:
            fail("%s records size != %d" % (name, e - s))
        else:
            ok("%s records size" % name)
        mine.append((s, e))
        total_bytes += e - s

        # exhibit bytes.
        raw_ex = open(os.path.join(PACKET_DIR, ex["hex"]), "rb").read()
        if raw_ex != data[s - 0x1000:e - 0x1000]:
            fail("%s .hex bytes differ from binary slice" % name)
        else:
            ok("%s .hex bytes" % name)

        # objdump regeneration (strip first 2 header lines: blank + path line).
        r = run(["objdump", "-d", "--start-address=%s" % hex(s),
                 "--stop-address=%s" % hex(e), BINARY])
        stored = open(os.path.join(PACKET_DIR, ex["objdump"]), "r").read().splitlines()[2:]
        if r.stdout.splitlines()[2:] != stored:
            fail("%s objdump regeneration differs" % name)
        else:
            ok("%s objdump regeneration" % name)

        # strict recount.
        sl = strict_lines(s, e)
        if len(sl) != ex.get("strict_instructions"):
            fail("%s strict %d != records %s" % (name, len(sl), ex.get("strict_instructions")))
        else:
            ok("%s strict recount" % name)
        total_strict += len(sl)

        # FDE bounds from .eh_frame.
        if fdes.get(s) != e - s:
            fail("%s eh_frame FDE size %s != %d" % (name, fdes.get(s), e - s))
        else:
            ok("%s eh_frame FDE" % name)

        # node resolution via .rela.dyn.
        name_va = rel.get(node + 0x08)
        handler = rel.get(node + 0x20)
        if handler != s:
            fail("%s node+0x20 addend %s != handler %s" % (name, hex(handler) if handler else None, hex(s)))
        else:
            ok("%s node handler slot" % name)
        if name_va is None:
            fail("%s node+0x08 missing" % name)
        else:
            # .rodata VA == file offset.
            end = data.index(b"\x00", name_va)
            leaf_name = data[name_va:end].decode()
            if leaf_name != name:
                fail("%s node name %r != %r" % (name, leaf_name, name))
            else:
                ok("%s node name" % name)

        # value-load triple.
        lines = objdump_lines(s, e)
        for (mn, sub) in LOAD_CHECKS[name]:
            found = any((mn in l.split("\t")[-1].split()[0] if "\t" in l else False) and sub in l
                        for _, _, l in lines)
            if not found:
                fail("%s missing load %s %s" % (name, mn, sub))
        if not any(f.startswith("%s missing load" % name) for f in failures):
            ok("%s load triple present" % name)

        # contract markers.
        if not any("0x20(%rsp)" in l and "%r9" in l for _, _, l in lines):
            fail("%s missing or-newp/newlen" % name)
        if not any(re.search(r"cmp\s+\$0x%x," % nbytes, l) for _, _, l in lines):
            fail("%s missing cmp $0x%x size" % (name, nbytes))
        if not any("mov" in l and "$0x16" in l for _, _, l in lines):
            fail("%s missing 0x16 return" % name)
        rets = [a for a, m, _ in lines if m == "ret"]
        if len(rets) != 1:
            fail("%s ret count %d != 1" % (name, len(rets)))
        # jump containment: every jmp/jcc target inside [s, e).
        bad_jumps = []
        calls = []
        for a, m, l in lines:
            parts = l.split("\t")[-1].split()
            if not parts:
                continue
            mn = parts[0]
            if mn == "call":
                tgt = re.findall(r"\b([0-9a-f]{7,})\b", parts[-1])
                if tgt:
                    calls.append(int(tgt[-1], 16))
            elif mn.startswith("j"):
                tgt = re.findall(r"\b([0-9a-f]{7,})\b", parts[-1])
                if tgt:
                    t = int(tgt[-1], 16)
                    if not (s <= t < e):
                        bad_jumps.append((hex(a), mn, hex(t)))
        if bad_jumps:
            fail("%s jumps outside FDE: %s" % (name, bad_jumps))
        else:
            ok("%s jump containment" % name)
        if any(c != 0x63F0D70 for c in calls):
            fail("%s non-stack-chk call: %s" % (name, [hex(c) for c in calls]))
        else:
            ok("%s calls only stack_chk_fail" % name)
        # direct E8 entries.
        if e8targets.get(s, 0) != 0:
            fail("%s direct E8 entries %d != 0" % (name, e8targets[s]))
        else:
            ok("%s 0 direct E8" % name)
        # .data file values where applicable.
        if name == "oversize_threshold":
            if struct.unpack_from("<Q", data, 0x64FFB70 - 0x3000)[0] != 0x800000:
                fail("oversize_threshold file qword != 0x800000")
            else:
                ok("oversize_threshold file qword 0x800000")
        if name == "mutex_max_spin":
            if struct.unpack_from("<Q", data, 0x64FFC98 - 0x3000)[0] != 0x258:
                fail("mutex_max_spin file qword != 0x258")
            else:
                ok("mutex_max_spin file qword 0x258")
        if name == "max_background_threads":
            if struct.unpack_from("<Q", data, 0x64FFBC8 - 0x3000)[0] != 0x1000:
                fail("max_background_threads file qword != 0x1000")
            else:
                ok("max_background_threads file qword 0x1000")
        if name == "dirty_decay_ms":
            if struct.unpack_from("<Q", data, 0x64FFB78 - 0x3000)[0] != 0x2710:
                fail("dirty_decay_ms file qword != 0x2710")
            else:
                ok("dirty_decay_ms file qword 0x2710")

    if total_bytes != rec.get("total_claimed_bytes"):
        fail("total bytes %d != records %s" % (total_bytes, rec.get("total_claimed_bytes")))
    else:
        ok("total bytes")
    if total_strict != rec.get("total_strict_instructions"):
        fail("total strict %d != records %s" % (total_strict, rec.get("total_strict_instructions")))
    else:
        ok("total strict")
    if rec.get("leaves_remaining_after") != 141:
        fail("leaves remaining %s != 141" % rec.get("leaves_remaining_after"))
    else:
        ok("leaves remaining 141")

    # disjointness.
    prior_roots = os.environ.get("HL267_PRIOR_ROOTS")
    if prior_roots:
        roots = prior_roots.split(":")
    else:
        roots = [os.path.join(ROOT, "research", "work-items")]
        roots += glob.glob(os.path.join(os.path.expanduser("~"), "workspace",
                                        "hl-wt-calls*", "research", "work-items"))
    priors = []
    ndirs = 0
    seen_dirs = set()
    for root in roots:
        for d in glob.glob(os.path.join(root, "*")):
            slug = os.path.basename(d)
            if slug == SLUG or slug in seen_dirs:
                continue
            rp = os.path.join(d, "records.json")
            if not os.path.isfile(rp):
                continue
            seen_dirs.add(slug)
            ndirs += 1
            try:
                collect_ranges(json.load(open(rp)), priors)
            except Exception:
                pass
    for (s, e) in mine:
        for (ps, pe) in priors:
            if s < pe and ps < e:
                fail("overlap: %s..%s overlaps prior %s..%s" % (hex(s), hex(e), hex(ps), hex(pe)))
    if not any(f.startswith("overlap") for f in failures):
        ok("disjoint from %d prior ranges (%d packet dirs)" % (len(priors), ndirs))
    for (s, e, lbl) in [(0x63B8820, 0x63B8D85, "#232 FDE"),
                        (0x63EC890, 0x63EC8A3, "#252 r28_wait"),
                        (0x63D9700, 0x63D987B, "#215 handler FDE")]:
        for (ms, me) in mine:
            if ms < e and s < me:
                fail("overlap with %s" % lbl)
    if not any(f.startswith("overlap with") for f in failures):
        ok("explicit overlap checks (#232, #252, #215)")

    # MANIFEST hashes.
    man_path = os.path.join(PACKET_DIR, "MANIFEST.sha256")
    try:
        man_lines = open(man_path).read().splitlines()
    except Exception as e:
        fail("cannot read MANIFEST: %s" % e)
        man_lines = []
    for line in man_lines:
        parts = line.split(None, 1)
        if len(parts) != 2:
            fail("bad MANIFEST line: %r" % line)
            continue
        want_hash, relpath = parts[0], parts[1].strip()
        fpath = os.path.normpath(os.path.join(PACKET_DIR, relpath))
        if not os.path.isfile(fpath):
            fail("MANIFEST missing file %s" % relpath)
            continue
        got = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
        if got != want_hash:
            fail("MANIFEST hash mismatch %s" % relpath)
    if man_lines and not any(f.startswith("MANIFEST") for f in failures):
        ok("MANIFEST hashes (%d entries)" % len(man_lines))

    if failures:
        print("VERIFIER FAIL (%d PASS, %d FAIL)" % (len(passes), len(failures)))
        for f in failures:
            print("FAIL: " + f)
        return 1
    print("VERIFIER OK: %d PASS, 0 FAIL" % len(passes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
