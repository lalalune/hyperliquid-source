"""Static verifier for RE-001-node115-lu-opt-hpa-leaves-bin-tails.

Byte reads only; never executes the node binary. Usage:
  python3 tools/node115_lu_opt_hpa_leaves_bin_tails.py [packet_dir] [binary]
Defaults: the packet dir under this repo and artifacts/node/115/hl-node.

Checks: binary identity, exhibit bytes, strict counts, objdump
regeneration (path-embedding header line stripped), .eh_frame FDE
bounds, .rela.dyn leaf slots and opt-children-array order, .data
file values, whole-.text E8 census, jump-target containment,
single-ret counts, disjointness against prior claimed ranges, and
MANIFEST hashes.

For tests only, the env var HL264_PRIOR_ROOTS (colon-separated
directories) overrides the prior-record scan roots; without it the
verifier scans the merged tree plus packets #183-#263 worktrees.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys

FAILS = []
PASSES = [0]


def fail(msg):
    FAILS.append(msg)
    print("FAIL:", msg)


def check(cond, msg):
    if cond:
        PASSES[0] += 1
    else:
        fail(msg)


def va_to_off(data, va):
    e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
    n = struct.unpack("<H", data[0x38:0x3a])[0]
    sz = struct.unpack("<H", data[0x36:0x38])[0]
    for i in range(n):
        p = e_phoff + i * sz
        t, fl, off, v, pa, fsz, msz, al = struct.unpack(
            "<IIQQQQQQ", data[p:p + 56])
        if t == 1 and v <= va < v + fsz:
            return off + (va - v)
    return None


STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
INSN_RE = re.compile(
    r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t([a-z][a-z0-9.]*)\s*(.*)$")
JUMP_MNEMS = {
    "jmp", "je", "jne", "ja", "jae", "jb", "jbe", "jl", "jle", "jg",
    "jge", "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz",
    "jrcxz",
}


def strict_count(lines):
    return sum(1 for l in lines if STRICT_RE.match(l))


def strip_header(lines):
    """Drop the objdump file-format line (embeds the invoked path)."""
    return [l for l in lines if "file format" not in l]


def parse_eh_frame(data):
    """Return {fde_start: fde_size} from .eh_frame (sdata4 pcrel)."""
    base = 0xca6ed8
    size = 0x77137c
    out = {}
    pos = 0
    while pos < size:
        length = struct.unpack_from("<I", data, base + pos)[0]
        if length == 0:
            break
        cie_id = struct.unpack_from("<I", data, base + pos + 4)[0]
        if cie_id != 0:
            p = base + pos + 8
            init = struct.unpack_from("<i", data, p)[0] + p
            rng = struct.unpack_from("<I", data, p + 4)[0]
            out[init] = rng
        pos += 4 + length
    return out


def collect_ranges(node, out, in_exhibits=False):
    """Range-only collector: exhibited windows only, never fde/census
    metadata. Mirrors packet #253's recursive collector plus the
    #259 range-only rule and the #260/#261 shape coverage."""
    if isinstance(node, dict):
        for key, val in node.items():
            if key in ("fde", "census", "cited", "survey", "callers",
                       "largest_caller_fde"):
                continue
            if key in ("exhibits", "windows"):
                items = val if isinstance(val, list) else (
                    val.values() if isinstance(val, dict) else [])
                for e in items:
                    if isinstance(e, dict):
                        def num(x):
                            return x if isinstance(x, int) else int(x, 16)

                        if "range" in e:
                            r = e["range"]
                            if isinstance(r, list):
                                out.append((num(r[0]), num(r[1])))
                            else:
                                a, b = r.split("..")
                                out.append((int(a, 16), int(b, 16)))
                        elif "start" in e and "end" in e:
                            out.append((num(e["start"]), num(e["end"])))
                collect_ranges(val, out, in_exhibits=True)
            else:
                collect_ranges(val, out, in_exhibits)
    elif isinstance(node, list):
        if in_exhibits and len(node) == 2 and all(
                isinstance(x, int) for x in node):
            out.append((node[0], node[1]))
        for item in node:
            collect_ranges(item, out, in_exhibits)


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def main():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        repo, "research/work-items/RE-001-node115-lu-opt-hpa-leaves-bin-tails")
    binary = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        repo, "artifacts/node/115/hl-node")
    data = open(binary, "rb").read()
    rec = json.load(open(os.path.join(packet_dir, "records.json")))

    # 1. Binary identity.
    check(len(data) == rec["binary_size"], "binary size mismatch")
    check(hashlib.sha256(data).hexdigest() == rec["binary_sha256"],
          "binary sha256 mismatch")

    # 2-4. Exhibit bytes, strict counts, objdump regeneration.
    exhibits = rec["exhibits"]
    check(len(exhibits) == 8, "expected 8 exhibits")
    claimed = []
    for e in exhibits:
        name = e["name"]
        s = int(e["range"].split("..")[0], 16)
        en = int(e["range"].split("..")[1], 16)
        check(e["start"] == s and e["end"] == en,
              "%s: start/end mismatch" % name)
        check(en - s == e["size"], "%s: size mismatch" % name)
        raw = open(os.path.join(packet_dir, e["hex"]), "rb").read()
        check(len(raw) == e["size"], "%s: hex size mismatch" % name)
        off = va_to_off(data, s)
        check(off is not None and data[off:off + len(raw)] == raw,
              "%s: hex bytes differ from binary" % name)
        lines = open(os.path.join(packet_dir, e["objdump"])).read() \
            .splitlines()
        check(strict_count(lines) == e["strict_instructions"],
              "%s: strict count %d != records %d" % (
                  name, strict_count(lines), e["strict_instructions"]))
        regen = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % hex(s),
             "--stop-address=%s" % hex(en), binary],
            capture_output=True, text=True).stdout.splitlines()
        check(strip_header(regen) == strip_header(lines),
              "%s: objdump regeneration differs" % name)
        claimed.append((s, en))

    check(sum(e["size"] for e in exhibits) == rec["total_claimed_bytes"],
          "total claimed bytes mismatch")
    check(sum(e["strict_instructions"] for e in exhibits) ==
          rec["total_strict_instructions"], "total strict mismatch")

    # 5. .eh_frame FDE bounds.
    fdes = parse_eh_frame(data)
    leaf_fdes = {
        0x636f7c0: 0x217, 0x636efa0: 0x217, 0x636f1c0: 0x217,
        0x636f3e0: 0x217, 0x636f600: 0x1b3,
    }
    for start, size in leaf_fdes.items():
        check(fdes.get(start) == size,
              "leaf FDE %#x size %#x != %#x" % (
                  start, fdes.get(start, -1), size))
    tails = {
        0x6352fc0: (0x63530d5, 0x6353608, 0x648),
        0x63e91c0: (0x63e92cd, 0x63e9491, 0x2d1),
        0x6365150: (0x6365212, 0x6365660, 0x510),
    }
    for fde_start, (t_start, t_end, fde_size) in tails.items():
        check(fdes.get(fde_start) == fde_size,
              "tail FDE %#x size mismatch" % fde_start)
        check(fde_start <= t_start and t_end <= fde_start + fde_size,
              "tail window outside its FDE %#x" % fde_start)

    # 6. .rela.dyn leaf slots + opt children array order.
    rela = {}
    for i in range(60723):
        roff, info, add = struct.unpack_from("<QQq", data, 0x6be8 + i * 24)
        rela[roff] = add

    def cstr(va):
        o = va_to_off(data, va)
        if o is None:
            return None
        e = data.index(b"\x00", o)
        return data[o:e].decode()

    leaves = rec["leaves"]
    check(len(leaves) == 5, "expected 5 leaves")
    prev_slot = None
    for leaf in leaves:
        node = int(leaf["node"], 16)
        handler = int(leaf["handler"].split("..")[0], 16)
        check(rela.get(node + 0x20) == handler,
              "%s: node+0x20 addend != handler" % leaf["leaf"])
        nameva = rela.get(node + 0x08)
        check(nameva is not None and cstr(nameva) ==
              leaf["leaf"].split("/", 1)[1],
              "%s: node+0x08 name mismatch" % leaf["leaf"])
        slot = 0x64de2e0 + leaf["opt_children_group"] * 40 + 32
        check(rela.get(slot) == handler,
              "%s: opt children group slot != handler" % leaf["leaf"])
        if prev_slot is not None:
            check(slot > prev_slot, "opt children slots out of order")
        prev_slot = slot

    # 7. .data file values (VA - 0x3000).
    vals = {
        0x64ffb00: (8, 0x10000), 0x64ffb08: (8, 0x1e6666),
        0x64ffb10: (4, 0x4000), 0x64ffb18: (8, 0x2710),
        0x64ffb20: (8, 0x1388),
    }
    for va, (width, want) in vals.items():
        fmt = "<Q" if width == 8 else "<I"
        got = struct.unpack_from(fmt, data, va - 0x3000)[0]
        check(got == want, ".data %#x = %#x != %#x" % (va, got, want))

    # 8. Whole-.text E8 census (single pass over E8 bytes).
    text_off = 0x1418300
    text_va = 0x1419300
    text = data[text_off:text_off + 0x4fd88a0]
    targets = {
        0x636f7c0: 0, 0x636efa0: 0, 0x636f1c0: 0, 0x636f3e0: 0,
        0x636f600: 0, 0x6352fc0: 23, 0x63e91c0: 2, 0x6365150: 29,
    }
    counts = {t: 0 for t in targets}
    e91c0_sites = []
    pos = text.find(b"\xe8")
    while pos != -1 and pos + 5 <= len(text):
        rel = struct.unpack_from("<i", text, pos + 1)[0]
        tgt = text_va + pos + 5 + rel
        if tgt in counts:
            counts[tgt] += 1
            if tgt == 0x63e91c0:
                e91c0_sites.append(text_va + pos)
        pos = text.find(b"\xe8", pos + 1)
    for tgt, want in targets.items():
        check(counts[tgt] == want,
              "E8 census %#x: %d != %d" % (tgt, counts[tgt], want))
    check(sorted(e91c0_sites) == [0x63ed254, 0x63eda85],
          "0x63e91c0 caller sites mismatch: %s" % e91c0_sites)

    # 9-10. Jump containment + ret counts per window.
    fde_of_window = [
        (0x636f7c0, 0x636f9d7, 0x636f7c0, 0x636f9d7, 1),
        (0x636efa0, 0x636f1b7, 0x636efa0, 0x636f1b7, 1),
        (0x636f1c0, 0x636f3d7, 0x636f1c0, 0x636f3d7, 1),
        (0x636f3e0, 0x636f5f7, 0x636f3e0, 0x636f5f7, 1),
        (0x636f600, 0x636f7b3, 0x636f600, 0x636f7b3, 1),
        (0x63530d5, 0x6353608, 0x6352fc0, 0x6353608, 1),
        (0x63e92cd, 0x63e9491, 0x63e91c0, 0x63e9491, 1),
        (0x6365212, 0x6365660, 0x6365150, 0x6365660, 0),
    ]
    allowed_outside = {0x63bd2c0, 0x63bcd20, 0x6364880}
    for e, (ws, we, fs, fe, want_rets) in zip(exhibits, fde_of_window):
        lines = open(os.path.join(packet_dir, e["objdump"])).read() \
            .splitlines()
        rets = 0
        for l in lines:
            m = INSN_RE.match(l)
            if not m:
                continue
            mnem, operand = m.group(2), m.group(3)
            if mnem == "ret":
                rets += 1
            if mnem in JUMP_MNEMS:
                check(not operand.startswith("*"),
                      "%s: indirect jump in window" % e["name"])
                tok = operand.split()[0] if operand.split() else ""
                try:
                    tgt = int(tok, 16)
                except ValueError:
                    fail("%s: unparsable jump target %r" % (e["name"], tok))
                    continue
                ok = fs <= tgt < fe or (
                    e["name"] == "bin_alloc_65150_remainder"
                    and tgt in allowed_outside)
                check(ok, "%s: jump %#x outside FDE" % (e["name"], tgt))
        check(rets == want_rets,
              "%s: ret count %d != %d" % (e["name"], rets, want_rets))

    # 11. Disjointness.
    priors = []
    roots = os.environ.get("HL264_PRIOR_ROOTS")
    if roots:
        roots = roots.split(":")
    else:
        import glob
        roots = glob.glob(os.path.expanduser(
            "~/workspace/hl-wt-calls*/research/work-items/*/records.json"))
        roots += glob.glob(os.path.join(
            repo, "research/work-items/*/records.json"))
    seen_slugs = set()
    for path in roots:
        try:
            doc = json.load(open(path))
        except Exception:
            continue
        slug = doc.get("packet") if isinstance(doc, dict) else None
        if not isinstance(slug, str):
            slug = json.dumps(slug, sort_keys=True) if slug else None
        if slug is not None and (slug in seen_slugs or
                                 slug == rec["packet"]):
            continue
        if slug is not None:
            seen_slugs.add(slug)
        collect_ranges(doc, priors)
    check(len(priors) > 0, "no prior ranges collected (scan broken?)")
    for (s, en) in claimed:
        for p in priors:
            if overlaps((s, en), p):
                fail("overlap with prior %#x..%#x" % p)
                break
    for i in range(len(claimed)):
        for j in range(i + 1, len(claimed)):
            check(not overlaps(claimed[i], claimed[j]),
                  "own windows %d/%d overlap" % (i, j))
    for (s, en) in [(0x63b8820, 0x63b8d85), (0x63ec890, 0x63ec8a3),
                    (0x63d9700, 0x63d987b), (0x6352fc0, 0x63530d5),
                    (0x63e91c0, 0x63e92cd), (0x6365150, 0x6365212)]:
        for (cs, ce) in claimed:
            check(not overlaps((cs, ce), (s, en)),
                  "overlap with explicit prior %#x..%#x" % (s, en))

    # 12. MANIFEST hashes.
    man = open(os.path.join(packet_dir, "MANIFEST.sha256")).read() \
        .splitlines()
    check(len(man) == 21, "MANIFEST entry count %d != 21" % len(man))
    for line in man:
        h, path = line.split(None, 1)
        path = path.strip()
        full = os.path.normpath(os.path.join(packet_dir, path))
        check(os.path.exists(full), "MANIFEST missing file %s" % path)
        if os.path.exists(full):
            got = hashlib.sha256(open(full, "rb").read()).hexdigest()
            check(got == h, "MANIFEST hash mismatch %s" % path)

    print("VERIFIER %s: %d PASS, %d FAIL" % (
        "OK" if not FAILS else "FAILED", PASSES[0], len(FAILS)))
    if FAILS:
        sys.exit(1)


if __name__ == "__main__":
    main()
