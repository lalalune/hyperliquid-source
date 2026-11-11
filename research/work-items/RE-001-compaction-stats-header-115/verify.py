#!/usr/bin/env python3
"""Self-check for this work item.  Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-stats-header-115/verify.py

Checks, in order (fails fast with a named check):
  1. artifact digest: work/hl-node-115.bin matches provenance/artifacts.json
  2. manifest: every packet file's SHA-256 matches MANIFEST.sha256
  3. excerpt regeneration: fresh objdump output is byte-for-byte the
     committed excerpt (the re-shipped excerpts were regenerated with
     the same command and diffed byte-for-byte against the source packet)
  4. excerpt bytes: every instruction line's bytes match the raw binary
     at the mapped file offset (program-header mapping)
  5. FDE lines: every line of frames.txt appears in a fresh readelf dump
  6. census: a fresh census run reproduces callers.tsv and relocations.txt
  7. records + derive_names + model spot check: the JSON parses,
     derive_names.py reproduces the pair table, the model's SECOND
     table matches it, and the spot-check block is rebuilt
     independently from the recorded formats, pair table and column
     order (not by calling the model)
  8. model tests: tests/test_compaction_stats_header_115.py exits 0
  9. literals: the pinned .rodata format/label/throw strings match
     the raw binary
 10. column order: re-derived from main.txt — the 13 map::at calls,
     the 7 inlined lower_bound + equality lookups, and the 20 stack
     varargs in reverse push order must give [label, 1, 3..21]
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
BIN = ROOT / "work" / "hl-node-115.bin"
PACKET = HERE

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
import census as census_mod
import compaction_stats_header_115 as model
import export_excerpts as export_mod

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + detail if detail else ""))
    if not ok:
        FAILURES.append(name)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _f, p_offset, p_vaddr, _p, p_filesz, _m, _a = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
    return loads


def vaddr_to_offset(loads, vaddr, size):
    for p_offset, p_vaddr, p_filesz in loads:
        if p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


INSTR_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)")
ADDR_RE = re.compile(r"^\s+([0-9a-f]+):")
EDI_RE = re.compile(r"mov\s+\$0x([0-9a-f]+),%edi")
AT_CALL_RE = re.compile(r"call\s+5eeb7f0\b")
AT_RESULT_RE = re.compile(r"mov\s+0x20\(%rax\),%([a-z0-9]+)")
AT_R9_RE = re.compile(r"mov\s+%rax,%r9")
FIND_CHECK_RE = re.compile(r"cmpl\s+\$0x([0-9a-f]+),0x20\(%r[a-z0-9]+\)")
FIND_JG_RE = re.compile(r"jg\s+5eee2e8\b")
FIND_LOOP_RE = re.compile(r"cmpl\s+\$0x([0-9a-f]+),0x20\(%r[a-z0-9]+\)")
FIND_RESULT_RE = re.compile(r"mov\s+0x48\(%r[a-z0-9]+\),%([a-z0-9]+)")
STORE_RE = re.compile(r"mov\s+%([a-z0-9]+),(?:0x([0-9a-f]+))?\(%rsp\)")
LOAD_RE = re.compile(r"mov\s+(?:0x([0-9a-f]+))?\(%rsp\),%([a-z0-9]+)")
PUSH_MEM_RE = re.compile(r"push\s+(?:0x([0-9a-f]+))?\(%rsp\)")
PUSH_REG_RE = re.compile(r"push\s+%([a-z0-9]+)")
PUSH_PAIR_RE = re.compile(r"push\s+0x20\(%r9\)")


def parse_main():
    """(addr, text) pairs for the instruction lines of main.txt."""
    lines = []
    for line in (PACKET / "main.txt").read_text().splitlines():
        m = ADDR_RE.match(line)
        if m:
            lines.append((int(m.group(1), 16), line))
    return lines


def derive_column_order():
    """Re-derive the header-row column order from main.txt.

    Returns (order, detail) where order is the list of column keys
    after the label, or (None, reason) on failure.
    """
    lines = parse_main()
    # Lookup definitions: (addr, key, result-register).  at() calls use
    # the nearest preceding `mov $key,%edi`; inlined finds use the
    # check constant of the `cmpl $key` + `jg 5eee2e8` pair (the loop
    # compares against key-1 with jle, i.e. lower_bound(key)).
    defs = []
    for i, (addr, text) in enumerate(lines):
        if AT_CALL_RE.search(text):
            key = None
            for j in range(i - 1, max(-1, i - 12), -1):
                m = EDI_RE.search(lines[j][1])
                if m:
                    key = int(m.group(1), 16)
                    break
            if key is None:
                return None, "at() call at %#x has no edi key" % addr
            reg = None
            for j in range(i + 1, min(len(lines), i + 6)):
                m = AT_RESULT_RE.search(lines[j][1])
                if m:
                    reg = m.group(1)
                    break
                if AT_R9_RE.search(lines[j][1]):
                    reg = "r9"
                    break
            if reg is None:
                return None, "at() call at %#x has no result" % addr
            defs.append((addr, key, reg))
        m = FIND_CHECK_RE.search(text)
        if m and i + 1 < len(lines) and FIND_JG_RE.search(lines[i + 1][1]):
            key = int(m.group(1), 16)
            loop_ok = any(
                FIND_LOOP_RE.search(lines[j][1])
                and int(FIND_LOOP_RE.search(lines[j][1]).group(1), 16)
                == key - 1
                for j in range(max(0, i - 40), i))
            if not loop_ok:
                return None, "find at %#x has no key-1 loop constant" % addr
            reg = None
            for j in range(i + 2, min(len(lines), i + 8)):
                m2 = FIND_RESULT_RE.search(lines[j][1])
                if m2:
                    reg = m2.group(1)
                    break
            if reg is None:
                return None, "find at %#x has no result" % addr
            defs.append((addr, key, reg))
    if len(defs) != 20:
        return None, "expected 20 lookups, got %d" % len(defs)
    # Slot stores: `mov %reg,0xS(%rsp)` resolves the register through
    # the most recent lookup definition before the store.
    slots = {}
    for addr, text in lines:
        m = STORE_RE.search(text)
        if not m:
            continue
        reg, slot = m.group(1), int(m.group(2), 16) if m.group(2) else 0
        prior = [d for d in defs if d[0] < addr and d[2] == reg]
        if not prior:
            continue
        slots[slot] = prior[-1][1]
    # Push phase: simulate rsp from 0; each push reads a slot at the
    # pre-push rsp, or a register (r13/r8/r9 from the lookup defs, or a
    # value reloaded from a slot by a `mov 0xN(%rsp),%reg` line).
    regmap = {}
    for addr, key, reg in defs:
        regmap[reg] = key
    push_keys = []
    rsp = 0
    started = False
    for addr, text in lines:
        if addr < 0x5EEE1AA:
            continue
        if re.search(r"\bcall\s+", text):
            break
        started = True
        m = LOAD_RE.search(text)
        if m:
            slot = rsp + (int(m.group(1), 16) if m.group(1) else 0)
            if slot not in slots:
                return None, "push-phase load of unknown slot %#x" % slot
            regmap[m.group(2)] = slots[slot]
            continue
        m = PUSH_MEM_RE.search(text)
        if m:
            slot = rsp + (int(m.group(1), 16) if m.group(1) else 0)
            if slot not in slots:
                return None, "push of unknown slot %#x" % slot
            push_keys.append(slots[slot])
            rsp -= 8
            continue
        if PUSH_PAIR_RE.search(text):
            if "r9" not in regmap:
                return None, "push 0x20(%r9) with unknown r9"
            push_keys.append(regmap["r9"])
            rsp -= 8
            continue
        m = PUSH_REG_RE.search(text)
        if m:
            if m.group(1) not in regmap:
                return None, "push of unknown register %s" % m.group(1)
            push_keys.append(regmap[m.group(1)])
            rsp -= 8
            continue
    if not started or len(push_keys) != 20:
        return None, "expected 20 pushes, got %d" % len(push_keys)
    # Stack varargs are in reverse push order; the label (r9 = *(rdx))
    # is the first vararg.
    order = list(reversed(push_keys))
    label_ok = any("mov    (%r15),%r9" in t for _, t in lines)
    if not label_ok:
        return None, "no mov (%r15),%r9 for the label vararg"
    return order, "lookups=%d pushes=%d" % (len(defs), len(push_keys))


def rebuild_spot_check(records):
    """Rebuild the spot-check block from records.json alone (no model)."""
    fmt = records["formats"]
    pairs = {e["key"]: e["second"]
             for e in records["pair_table"]["entries"]}
    cols = ["Level"] + [pairs[k] for k in records["columns"]["order"][1:]]
    header = fmt["header"]["format"] % "default"
    row = fmt["row"]["format"] % tuple(cols)
    # The snprintf budgets (2000) never bind for this short block.
    assert len(header) < 2000 and len(header) + len(row) < 2000
    return header + row + "-" * len(row) + "\n"


def main():
    data = BIN.read_bytes()
    loads = load_segments(data)

    # 1. artifact digest
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    check("artifact digest", sha256_file(BIN) == want, want[:12])

    # 2. manifest
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    bad = [n for n, d in manifest.items()
           if sha256_file(PACKET / n) != d]
    extra = sorted(p.name for p in PACKET.iterdir()
                   if p.is_file() and p.name not in manifest
                   and p.name != "MANIFEST.sha256")
    check("manifest", not bad and not extra,
          "bad=%s extra=%s" % (bad, extra))

    # 3. excerpt regeneration
    regen_bad = []
    for name, (start, stop) in export_mod.EXCERPTS.items():
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            cwd=str(ROOT), check=True, capture_output=True, text=True).stdout
        if (PACKET / name).read_text() != out:
            regen_bad.append(name)
    check("excerpt regeneration", not regen_bad, str(regen_bad))

    # 4. excerpt bytes vs raw binary
    n_lines = n_bad = 0
    for path in sorted(PACKET.glob("*.txt")):
        if path.name in ("frames.txt", "callers.tsv", "relocations.txt"):
            continue
        for line in path.read_text().splitlines():
            m = INSTR_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            n_lines += 1
            off = vaddr_to_offset(loads, addr, len(raw))
            if off is None or data[off:off + len(raw)] != raw:
                n_bad += 1
                if n_bad <= 5:
                    print("  byte mismatch %s:%#x" % (path.name, addr))
    check("excerpt bytes vs binary", n_bad == 0,
          "%d lines, %d bad" % (n_lines, n_bad))

    # 5. FDE lines
    frames_out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        check=True, capture_output=True, text=True).stdout
    missing = [ln for ln in (PACKET / "frames.txt").read_text().splitlines()
               if ln.strip() and ln not in frames_out]
    check("FDE lines", not missing, str(missing))

    # 6. census reproduction
    cdata, exec_segs, cloads = census_mod.load_segments()
    calls = census_mod.scan_calls(cdata, exec_segs, census_mod.fde_ranges())
    stored = census_mod.scan_stored_qwords(cdata, cloads)
    rels = census_mod.scan_relative_relocations()
    tsv_lines = ["target\tkind\tsite"]
    for _name, target in census_mod.TARGETS.items():
        for kind in ("call", "jmp"):
            for site in calls[target][kind]:
                tsv_lines.append("0x%x\t%s\t0x%x" % (target, kind, site))
    rel_lines = []
    for _name, target in census_mod.TARGETS.items():
        rel_lines.append("0x%x relative_records:%s" % (
            target, (" " + " ".join("0x%x" % o for o in rels[target]))
            if rels[target] else " none"))
        rel_lines.append("0x%x stored_qwords:%s" % (
            target, (" " + " ".join(
                "0x%x%s" % (v, " (in .rela.dyn, addend field)" if r else "")
                for v, r in stored[target])) if stored[target] else " none"))
    tsv_ok = (PACKET / "callers.tsv").read_text().splitlines() == tsv_lines
    rel_ok = (PACKET / "relocations.txt").read_text().splitlines() == rel_lines
    check("census reproduction", tsv_ok and rel_ok,
          "tsv=%s rel=%s" % (tsv_ok, rel_ok))

    # 7. records + derive_names + model spot check
    records = json.loads((PACKET / "records.json").read_text())
    proc = subprocess.run(
        [sys.executable, str(HERE / "derive_names.py")],
        capture_output=True, text=True)
    derived = json.loads(proc.stdout) if proc.returncode == 0 else {}
    pairs_ok = ([(e["key"], e["first"], e["second"])
                 for e in derived.get("pair_table", [])]
                == [(e["key"], e["first"], e["second"])
                    for e in records["pair_table"]["entries"]])
    model_pairs_ok = (
        [(k, model.SECOND[k]) for k in sorted(model.SECOND)]
        == [(e["key"], e["second"])
            for e in records["pair_table"]["entries"]])
    model_cols_ok = model.COLUMN_KEYS == records["columns"]["order"][1:]
    rebuilt = rebuild_spot_check(records)
    spot = records["model_spot_check"]
    spot_ok = rebuilt == spot["expected"]
    model_spot_ok = (model.format_header(
        spot["input"]["name"], spot["input"]["label"]).decode("utf-8")
        == spot["expected"])
    check("records + derive_names + spot check",
          proc.returncode == 0 and pairs_ok and model_pairs_ok
          and model_cols_ok and spot_ok and model_spot_ok,
          "derive=%d pairs=%s model_pairs=%s cols=%s rebuild=%s model=%s"
          % (proc.returncode, pairs_ok, model_pairs_ok, model_cols_ok,
             spot_ok, model_spot_ok))

    # 8. model tests
    proc = subprocess.run(
        [sys.executable, "tests/test_compaction_stats_header_115.py"],
        cwd=str(ROOT), capture_output=True, text=True)
    check("model tests", proc.returncode == 0,
          proc.stdout.strip().splitlines()[-1] if proc.stdout
          else proc.stderr[-200:])

    # 9. literals: pinned .rodata strings match the raw binary.
    def read_vaddr(addr, size):
        off = vaddr_to_offset(loads, addr, size)
        assert off is not None, hex(addr)
        return data[off:off + size]

    lit_ok = True
    for addr, want_bytes in (
            (0x4382DD, b"\n** Compaction Stats [%s] **\n\x00"),
            (0x9572F8, b"%s    %s   %s     %s %s  %s %s %s %s %s %s %s %s "
                      b"%s %s %s %s %s %s %s %s\n\x00"),
            (0x43616F, b"%s\n\x00"),
            (0x4408A7, b"map::at\x00"),
            (0x44D03D, b"Level\x00"),
            (0x43E67F, b"Priority\x00")):
        if read_vaddr(addr, len(want_bytes)) != want_bytes:
            lit_ok = False
            print("  literal mismatch at %#x" % addr)
    check("literals", lit_ok)

    # 10. column order re-derived from main.txt
    order, detail = derive_column_order()
    check("column order", order == [1] + list(range(3, 22)),
          "%s order=%s" % (detail, order))

    print("ALL CHECKS PASSED" if not FAILURES
          else "FAILURES: %s" % ", ".join(FAILURES))
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
