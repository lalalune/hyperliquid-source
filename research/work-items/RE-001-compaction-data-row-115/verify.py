#!/usr/bin/env python3
"""Self-check for this work item.  Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-data-row-115/verify.py

Checks, in order (fails fast with a named check):
  1. artifact digest: work/hl-node-115.bin matches provenance/artifacts.json
  2. manifest: every packet file's SHA-256 matches MANIFEST.sha256
  3. excerpt regeneration: fresh objdump output is byte-for-byte the
     committed excerpt (the re-shipped label_assign excerpt was
     regenerated with the same command and diffed byte-for-byte against
     the source packet)
  4. excerpt bytes: every instruction line's bytes match the raw binary
     at the mapped file offset (program-header mapping)
  5. FDE lines: every line of frames.txt appears in a fresh readelf dump
  6. census: a fresh census run reproduces callers.tsv and relocations.txt
  7. records + spot check: the JSON parses and the spot-check block is
     rebuilt independently from the recorded format, column order and
     rendered strings (not by calling the model), and the model
     reproduces the same row
  8. model tests: tests/test_compaction_data_row_115.py exits 0
  9. literals: the pinned .rodata format/label/throw strings and the
     pinned doubles match the raw binary
 10. column order: re-derived from main.txt — the 14 map::at calls,
     the 7 inlined lower_bound + equality lookups, the 8 xmm varargs
     and the 13 stack varargs in reverse push order must give
     [label, 1..21]
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
import compaction_data_row_115 as model
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
ESI_KEY_RE = re.compile(r"mov\s+\$0x([0-9a-f]+),%esi")
AT_CALL_RE = re.compile(r"call\s+5eebac0\b")
AT_DOUBLE_RE = re.compile(r"movsd\s+\(%rax\),%(xmm[0-9]+)")
STORE_DBL_RE = re.compile(r"movsd\s+%(xmm[0-9]+),(?:0x([0-9a-f]+))?\(%rsp\)")
CVT64_RE = re.compile(r"cvttsd2si\s+\(%rax\),%rsi")
CVT64_XMM_RE = re.compile(r"cvttsd2si\s+%xmm[0-9]+,%rsi")
CVT32_RE = re.compile(r"cvttsd2si\s+\(%rax\),%eax")
STORE_INT_RE = re.compile(r"mov\s+%eax,(?:0x([0-9a-f]+))?\(%rsp\)")
LEA_SLOT_RE = re.compile(r"lea\s+(?:0x([0-9a-f]+))?\(%rsp\),%(r1[234])")
MOV_REG_RDI_RE = re.compile(r"mov\s+%(r1[234]),%rdi")
FMT_CALL_RE = re.compile(r"call\s+(61d0940|61d0ba0)\b")
FIND_CHECK_RE = re.compile(r"cmpl\s+\$0x([0-9a-f]+),0x20\(%r[a-z0-9]+\)")
FIND_JG_RE = re.compile(
    r"jg\s+5eed(d18|d37|d56|c90|cb3|cd6|cf9)\b")
FIND_LOOP_RE = re.compile(r"cmpl\s+\$0x([0-9a-f]+),0x20\(%r[a-z0-9]+\)")
FIND_RESULT_RE = re.compile(r"movsd\s+0x28\(%r[a-z0-9]+\),%(xmm[0-9]+)")
FIND_CVT_RE = re.compile(r"cvttsd2si\s+0x28\(%r[a-z0-9]+\),%([a-z0-9]+)")
LOAD_RE = re.compile(r"mov\s+(?:0x([0-9a-f]+))?\(%rsp\),%([a-z0-9]+)")
XMM_LOAD_RE = re.compile(
    r"movsd\s+(?:0x([0-9a-f]+))?\(%rsp\),%(xmm[0-9]+)")
PUSH_MEM_RE = re.compile(r"push\s+(?:0x([0-9a-f]+))?\(%rsp\)")
PUSH_REG_RE = re.compile(r"push\s+%([a-z0-9]+)")
MOV_DEREF_R9_RE = re.compile(r"mov\s+\(%rax\),%r9")
SNPRINTF_RE = re.compile(r"call\s+63f0f30\b")
SUB_RSP_RE = re.compile(r"sub\s+\$0x8,%rsp")
FMT_CONV_RE = re.compile(r"%([-0-9.]+)([sdif])")
REG64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
         "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
         "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
         "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15"}


def reg64(name):
    """Normalize a register name to its 64-bit form (eax -> rax)."""
    return REG64.get(name, name)


def parse_main():
    """(addr, text) pairs for the instruction lines of main.txt."""
    lines = []
    for line in (PACKET / "main.txt").read_text().splitlines():
        m = ADDR_RE.match(line)
        if m:
            lines.append((int(m.group(1), 16), line))
    return lines


def derive_vararg_order():
    """Re-derive the row's vararg order from main.txt.

    Returns (order, detail) where order is ["label", 1..21] in format
    order, or (None, reason) on failure.
    """
    lines = parse_main()
    # lea 0xS(%rsp),%r12/%r13/%r14 assignments (string temporaries).
    lea_slots = {}
    for _addr, text in lines:
        m = LEA_SLOT_RE.search(text)
        if m:
            lea_slots[m.group(2)] = int(m.group(1), 16) if m.group(1) else 0
    # Lookup definitions: key -> ("slot", S) | ("reg", r) | ("str", S).
    # at() calls use the nearest preceding `mov $key,%esi`; inlined
    # finds use the check constant of the `cmpl $key` + `jg <throw>`
    # pair (the loop compares against key-1 with jle, i.e.
    # lower_bound(key)).
    slot_to_key = {}
    reg_to_key = {}
    str_to_key = {}
    # Register -> key for the cvttsd2si conversions the inlined finds
    # feed into the push phase (key 1's conversion happens mid-phase,
    # after %eax was reused for key 16, so the push-phase scan must
    # re-apply it when it reaches the instruction).
    cvt_reg_to_key = {}
    n_at = n_find = 0
    for i, (addr, text) in enumerate(lines):
        if AT_CALL_RE.search(text):
            key = None
            for j in range(i - 1, max(-1, i - 12), -1):
                m = ESI_KEY_RE.search(lines[j][1])
                if m:
                    key = int(m.group(1), 16)
                    break
            if key is None:
                return None, "at() call at %#x has no esi key" % addr
            n_at += 1
            done = False
            for j in range(i + 1, min(len(lines), i + 10)):
                t = lines[j][1]
                if CVT64_RE.search(t) or CVT64_XMM_RE.search(t):
                    for k in range(j + 1, min(len(lines), j + 8)):
                        if FMT_CALL_RE.search(lines[k][1]):
                            reg = None
                            for q in range(k - 1, max(-1, k - 6), -1):
                                m3 = MOV_REG_RDI_RE.search(lines[q][1])
                                if m3:
                                    reg = m3.group(1)
                                    break
                            if reg is None or reg not in lea_slots:
                                return None, (
                                    "fmt call at %#x has no rdi slot"
                                    % lines[k][0])
                            str_to_key[lea_slots[reg]] = key
                            done = True
                            break
                    break
                m = AT_DOUBLE_RE.search(t)
                if m:
                    xmm = m.group(1)
                    found = False
                    for k in range(j + 1, min(len(lines), j + 4)):
                        m2 = STORE_DBL_RE.search(lines[k][1])
                        if m2 and m2.group(1) == xmm:
                            slot = int(m2.group(2), 16) if m2.group(2) else 0
                            slot_to_key[slot] = key
                            done = True
                            found = True
                            break
                    if found:
                        break
                    # no store follows: the double is consumed by a
                    # conversion (key 3's u64 path) — keep scanning.
                    continue
                if CVT32_RE.search(t):
                    for k in range(j + 1, min(len(lines), j + 4)):
                        m2 = STORE_INT_RE.search(lines[k][1])
                        if m2:
                            slot = int(m2.group(1), 16) if m2.group(1) else 0
                            slot_to_key[slot] = key
                            done = True
                            break
                    break
            if not done:
                return None, "at() call at %#x has no result" % addr
            continue
        m = FIND_CHECK_RE.search(text)
        if m and i + 1 < len(lines) and FIND_JG_RE.search(lines[i + 1][1]):
            key = int(m.group(1), 16)
            loop_ok = any(
                FIND_LOOP_RE.search(lines[j][1])
                and int(FIND_LOOP_RE.search(lines[j][1]).group(1), 16)
                == key - 1
                for j in range(max(0, i - 40), i))
            if key == 1:
                loop_ok = loop_ok or any(
                    "test" in lines[j][1] and "%r9d" in lines[j][1]
                    for j in range(max(0, i - 40), i))
            if not loop_ok:
                return None, "find at %#x has no key-1 loop constant" % addr
            n_find += 1
            done = False
            # The result can sit up to ~18 lines past the check: the
            # key-1 conversion happens inside the push phase, after
            # several pushes (0x5eedbb0 vs the check at 0x5eedb61).
            for j in range(i + 2, min(len(lines), i + 25)):
                t = lines[j][1]
                m2 = FIND_RESULT_RE.search(t)
                if m2:
                    xmm = m2.group(1)
                    for k in range(j + 1, min(len(lines), j + 4)):
                        m3 = STORE_DBL_RE.search(lines[k][1])
                        if m3 and m3.group(1) == xmm:
                            slot = int(m3.group(2), 16) if m3.group(2) else 0
                            slot_to_key[slot] = key
                            done = True
                            break
                    break
                m2 = FIND_CVT_RE.search(t)
                if m2:
                    reg_to_key[reg64(m2.group(1))] = key
                    cvt_reg_to_key[reg64(m2.group(1))] = key
                    done = True
                    break
            if not done:
                return None, "find at %#x has no result" % addr
    if n_at != 14 or n_find != 7:
        return None, "expected 14 at() + 7 finds, got %d + %d" % (n_at, n_find)
    if len(slot_to_key) + len(reg_to_key) + len(str_to_key) != 21:
        return None, "expected 21 lookup results, got slots=%s regs=%s strs=%s" % (
            sorted(slot_to_key), sorted(reg_to_key), sorted(str_to_key))
    # String temporaries: r15 holds the 0xe0 string's data pointer
    # (loaded at 0x5eed779), r8 holds the 0xa0 string's data pointer
    # (loaded at 0x5eedacf); the 0xc0 string's data pointer is stored
    # at slot 0x18 (0x5eed7a7).
    for slot, key in str_to_key.items():
        if slot == 0xE0:
            reg_to_key["r15"] = key
        elif slot == 0xA0:
            reg_to_key["r8"] = key
        elif slot == 0xC0:
            slot_to_key[0x18] = key
        else:
            return None, "unexpected string slot %#x" % slot
    # Push phase: simulate rsp from the `sub $0x8,%rsp` (0x5eedb6b)
    # until the snprintf call; each push reads a slot at the pre-push
    # rsp or a register.
    push_keys = []
    xmm_to_key = {}
    label_ok = False
    rsp = 0
    started = False
    for addr, text in lines:
        if addr < 0x5EEDB6B:
            continue
        if SNPRINTF_RE.search(text):
            break
        started = True
        if SUB_RSP_RE.search(text):
            rsp -= 8
            continue
        m = XMM_LOAD_RE.search(text)
        if m:
            slot = rsp + (int(m.group(1), 16) if m.group(1) else 0)
            if slot not in slot_to_key:
                return None, "xmm load of unknown slot %#x" % slot
            xmm_to_key[m.group(2)] = slot_to_key[slot]
            continue
        # A cvttsd2si mid-phase re-targets a register: key 1's
        # conversion at 0x5eedbb0 sets %eax after %eax was reused for
        # key 16, so re-apply the find's register mapping here.
        m = FIND_CVT_RE.search(text)
        if m and reg64(m.group(1)) in cvt_reg_to_key:
            reg_to_key[reg64(m.group(1))] = cvt_reg_to_key[reg64(m.group(1))]
            continue
        m = LOAD_RE.search(text)
        if m:
            # A load into %rdi is the snprintf destination-pointer
            # setup (mov 0x90(%rsp),%rdi reads slot 0x20, the saved
            # out pointer), not a vararg.
            if reg64(m.group(2)) == "rdi":
                continue
            slot = rsp + (int(m.group(1), 16) if m.group(1) else 0)
            if slot == 0x28:
                reg_to_key[reg64(m.group(2))] = "label_ptr"
            elif slot in slot_to_key:
                reg_to_key[reg64(m.group(2))] = slot_to_key[slot]
            else:
                return None, "push-phase load of unknown slot %#x" % slot
            continue
        if MOV_DEREF_R9_RE.search(text):
            if reg_to_key.get("rax") != "label_ptr":
                return None, "mov (%rax),%r9 without label_ptr in rax"
            reg_to_key["r9"] = "label"
            label_ok = True
            continue
        m = PUSH_MEM_RE.search(text)
        if m:
            slot = rsp + (int(m.group(1), 16) if m.group(1) else 0)
            if slot not in slot_to_key:
                return None, "push of unknown slot %#x" % slot
            push_keys.append(slot_to_key[slot])
            rsp -= 8
            continue
        m = PUSH_REG_RE.search(text)
        if m:
            if reg64(m.group(1)) not in reg_to_key:
                return None, "push of unknown register %s" % m.group(1)
            push_keys.append(reg_to_key[reg64(m.group(1))])
            rsp -= 8
            continue
    if not started or len(push_keys) != 13:
        return None, "expected 13 pushes, got %d" % len(push_keys)
    if len(xmm_to_key) != 8:
        return None, "expected 8 xmm varargs, got %d" % len(xmm_to_key)
    if not label_ok or reg_to_key.get("r9") != "label":
        return None, "no mov (%rax),%r9 for the label vararg"
    # Assign conversions in format order: %f takes xmm0..xmm7 then
    # stack args; %d/%s takes r9 (label) then stack args.
    fmt = json.loads((PACKET / "records.json").read_text())["formats"]["row"]["format"]
    stack_args = list(reversed(push_keys))
    si = 0
    order = []
    for m in FMT_CONV_RE.finditer(fmt):
        kind = m.group(2)
        if kind == "f":
            # count the %f conversions seen so far
            n_f = sum(1 for c in FMT_CONV_RE.finditer(fmt[:m.start()])
                      if c.group(2) == "f")
            if n_f < 8:
                order.append(xmm_to_key["xmm%d" % n_f])
            else:
                order.append(stack_args[si])
                si += 1
        else:
            if not order:
                order.append("label")
            else:
                order.append(stack_args[si])
                si += 1
    if si != len(stack_args):
        return None, "stack args left over: %d of %d" % (si, len(stack_args))
    return order, "at=%d finds=%d pushes=%d xmm=%d" % (
        n_at, n_find, len(push_keys), len(xmm_to_key))


def rebuild_spot_check(records):
    """Rebuild the spot-check row from records.json alone (no model).

    Walks the recorded row format conversion by conversion, keeping
    the literal text between conversions (spaces, the '/' between
    keys 1 and 2, the trailing newline), and renders each conversion
    from the per-key format with the recorded input values: the label
    for the first %s, int truncation for %d, the recorded rendered
    strings for %s, and the recorded doubles for %f.
    """
    spot = records["model_spot_check"]
    metrics = {int(k): v for k, v in spot["input"]["metrics"].items()}
    rendered = spot["input"]["rendered_strings"]
    fmt = records["formats"]["row"]["format"]
    cols = records["columns"]["per_key"]
    assert [c["key"] for c in cols] == list(range(1, 22))
    values = [spot["input"]["label"]]
    for c in cols:
        if c["format"].endswith("s"):
            values.append(rendered[str(c["key"])])
        elif c["format"].endswith("d"):
            values.append(int(metrics[c["key"]]))
        else:
            values.append(metrics[c["key"]])
    out = []
    pos = 0
    vi = 0
    for m in FMT_CONV_RE.finditer(fmt):
        out.append(fmt[pos:m.start()])
        out.append(m.group(0) % values[vi])
        vi += 1
        pos = m.end()
    out.append(fmt[pos:])
    assert vi == len(values), "format has %d conversions, %d values" % (
        vi, len(values))
    return "".join(out)


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

    # 7. records + spot check
    records = json.loads((PACKET / "records.json").read_text())
    rebuilt = rebuild_spot_check(records)
    spot = records["model_spot_check"]
    spot_ok = rebuilt == spot["expected"]
    metrics = {int(k): v for k, v in spot["input"]["metrics"].items()}
    model_spot_ok = (model.format_row(spot["input"]["label"], metrics)
                     == spot["expected"])
    model_cols_ok = model.COLUMN_KEYS == records["columns"]["order"][1:]
    model_names_ok = (
        [(k, model.FIRST[k]) for k in sorted(model.FIRST)]
        == [(e["key"], e["name"])
            for e in records["columns"]["per_key"]])
    check("records + spot check",
          spot_ok and model_spot_ok and model_cols_ok and model_names_ok,
          "rebuild=%s model=%s cols=%s names=%s"
          % (spot_ok, model_spot_ok, model_cols_ok, model_names_ok))

    # 8. model tests
    proc = subprocess.run(
        [sys.executable, "tests/test_compaction_data_row_115.py"],
        cwd=str(ROOT), capture_output=True, text=True)
    check("model tests", proc.returncode == 0,
          proc.stdout.strip().splitlines()[-1] if proc.stdout
          else proc.stderr[-200:])

    # 9. literals: pinned .rodata strings and doubles match the binary.
    def read_vaddr(addr, size):
        off = vaddr_to_offset(loads, addr, size)
        assert off is not None, hex(addr)
        return data[off:off + size]

    lit_ok = True
    for addr, want_bytes in (
            (0x96C040, b"%4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f "
                      b"%8.1f %9.1f %5.1f %8.1f %8.1f %9.2f %17.2f %9d "
                      b"%8.3f %7s %6s %9.1f %9.1f\n\x00"),
            (0x43338F, b"%li\x00"),
            (0x43C8B2, b"%liK\x00"),
            (0x44B579, b"%liM\x00"),
            (0x439651, b"%liG\x00"),
            (0x4311E3, b"%.2f %s\x00"),
            (0x43B717, b"KB\x00"),
            (0x43756A, b"MB\x00"),
            (0x436386, b"GB\x00"),
            (0x43A777, b"TB\x00"),
            (0x4408A7, b"map::at\x00"),
            (0x43E67D, b"L\x00"),
            (0x43F948, b"Sum\x00"),
            (0x441A38, b"Int\x00"),
            (0x44FD1A, b"Bottom\x00"),
            (0x43A5D9, b"Low\x00"),
            (0x4409FD, b"High\x00"),
            (0x4487BB, b"User\x00"),
            (0x432082, b"Invalid\x00")):
        if read_vaddr(addr, len(want_bytes)) != want_bytes:
            lit_ok = False
            print("  literal mismatch at %#x" % addr)
    for addr, want in ((0x459360, 2.0 ** 63),
                      (0x459168, 1.0 / 1024.0),
                      (0x4599E0, 1024.0)):
        got = struct.unpack_from("<d", data,
                                 vaddr_to_offset(loads, addr, 8))[0]
        if got != want:
            lit_ok = False
            print("  double mismatch at %#x: %r != %r" % (addr, got, want))
    check("literals", lit_ok)

    # 10. column order re-derived from main.txt
    order, detail = derive_vararg_order()
    check("column order", order == ["label"] + list(range(1, 22)),
          "%s order=%s" % (detail, order))

    print("ALL CHECKS PASSED" if not FAILURES
          else "FAILURES: %s" % ", ".join(FAILURES))
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
